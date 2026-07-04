# Python filters — cookbook

A big pile of ready-to-adapt `match(flow)` filters, from one-liners to full
attack detectors, for both HTTP and TCP services. For the full API and semantics
see [PYFILTERS.md](PYFILTERS.md); this file is all worked examples.

Every example is copy-pasteable. Each is tagged:

- **Alert** — returns a reason string; shows up on the Alerts page. Works on any
  filter (async or Blocking).
- **Blocking** — drops or rewrites the current message in real time. Requires the
  **Blocking** checkbox on the filter. Inline blocking/rewriting works on TCP
  requests **and** responses, and on HTTP **requests**; HTTP *responses* are
  already forwarded before filters run, so a response-side HTTP filter can only
  Alert.

Quick reminder of return values:

| return | effect |
|---|---|
| `False` / `None` | ignore |
| `"reason"` | Alert |
| `{"drop": True, "reason": "..."}` | drop this message now (needs Blocking) |
| assign `flow.body` / `flow.content` | rewrite this message (needs Blocking) |

`match(flow)` runs once per message on **both directions**. Branch on
`flow.is_request` / `flow.is_response`, or set a module-level
`DIRECTION = "request"` / `"response"` and Janus skips the other side. Module-level
variables persist across calls (use them to count/correlate); `flow.conn` is
per-TCP-connection state, private to each filter.

---

## Table of contents

- [HTTP](#http)
  1. [Alert on an admin endpoint](#1-alert-on-an-admin-endpoint) · **Alert**
  2. [Suspicious User-Agent](#2-suspicious-user-agent) · **Alert**
  3. [SQLi / traversal probing in the URL](#3-sqli--traversal-probing-in-the-url) · **Alert**
  4. [Inspect a JSON body (None-safe)](#4-inspect-a-json-body-none-safe) · **Alert**
  5. [A flag-ID appears in a request](#5-a-flag-id-appears-in-a-request) · **Alert**
  6. [A flag leaks in a response](#6-a-flag-leaks-in-a-response) · **Alert**
  7. [Block a request outright](#7-block-a-request-outright) · **Blocking**
  8. [Block path traversal on the way in](#8-block-path-traversal-on-the-way-in) · **Blocking**
  9. [Rewrite a request body](#9-rewrite-a-request-body) · **Blocking**
  10. [Second login onward (stateful, SNAT-safe)](#10-second-login-onward-stateful-snat-safe) · **Alert**
  11. [Login reusing a registered password](#11-login-reusing-a-registered-password) · **Blocking**
  12. [Correlate request → response](#12-correlate-request--response) · **Alert**
- [TCP / byte streams](#tcp--byte-streams)
  13. [Alert when a chunk carries a flag](#13-alert-when-a-chunk-carries-a-flag) · **Alert**
  14. [Block a raw command by content](#14-block-a-raw-command-by-content) · **Blocking**
  15. [Parse a line protocol by hand](#15-parse-a-line-protocol-by-hand) · **Alert**
  16. [Parse a CLI menu with flow.commands](#16-parse-a-cli-menu-with-flowcommands) · **Blocking**
  17. [Block "get vip" on a flag-ID flight](#17-block-get-vip-on-a-flag-id-flight) · **Blocking**
  18. [Only the owner may read the vip (auth tracking)](#18-only-the-owner-may-read-the-vip-auth-tracking) · **Blocking**
  19. [Second flag-ID login on a connection](#19-second-flag-id-login-on-a-connection) · **Blocking**
  20. [Redact a flag from a TCP response](#20-redact-a-flag-from-a-tcp-response) · **Blocking**
  21. [Password reuse across connections](#21-password-reuse-across-connections) · **Alert**
  22. [Length-prefixed binary framing](#22-length-prefixed-binary-framing) · **Alert**

---

## HTTP

### 1. Alert on an admin endpoint

The simplest possible filter: return a string and it becomes an Alert. `flow` is
forgiving — missing fields read as `""`, so no `KeyError`.

```python
def match(flow):
    if flow.method == "POST" and "/admin" in flow.path:
        return "POST to an admin endpoint"
    return False
```

### 2. Suspicious User-Agent

Header access is case-insensitive and never raises on a missing header.

```python
def match(flow):
    ua = flow.header("user-agent").lower()          # missing -> ""
    if "sqlmap" in ua or "nikto" in ua or "curl" in ua:
        return "scanner user-agent: %s" % ua
    return False
```

### 3. SQLi / traversal probing in the URL

`flow.query` parses the query string; `.all(name)` returns every value.

```python
NEEDLES = ("' or ", " union ", "../", "..\\", "<script")

def match(flow):
    hay = (flow.url + " " + flow.body).lower()
    hit = next((n for n in NEEDLES if n in hay), None)
    if hit:
        return "injection-ish payload: %r" % hit
    return False
```

### 4. Inspect a JSON body (None-safe)

`flow.json()` returns the parsed body or `None`; guard with `or {}`.

```python
def match(flow):
    data = flow.json() or {}
    role = data.get("role")
    if role in ("admin", "root"):
        return "privilege escalation attempt (role=%s)" % role
    return False
```

### 5. A flag-ID appears in a request

Janus tags each message with whether it contains one of *your* current flag-IDs.
A flag-ID in a **request** usually means someone is targeting a specific victim.

```python
DIRECTION = "request"

def match(flow):
    if flow.contains_flagid:
        return "request references one of our flag-IDs: %s %s" % (flow.method, flow.path)
    return False
```

### 6. A flag leaks in a response

`flow.flagged` means the message body contains an actual flag. Seeing that on a
**response** is an exfiltration signal. (HTTP responses are alert-only — to stop
the leak on a TCP service, see example 20.)

```python
DIRECTION = "response"

def match(flow):
    if flow.flagged:
        return "flag left the service in a %s response" % flow.status
    return False
```

### 7. Block a request outright

Return `{"drop": True}` and mark the filter **Blocking** to stop the request
before it reaches the backend (a 403 for HTTP).

```python
def match(flow):
    if flow.path.startswith("/internal/") and flow.header("x-internal") == "":
        return {"drop": True, "reason": "external hit on an internal-only route"}
    return False
```

### 8. Block path traversal on the way in

```python
def match(flow):
    if "../" in flow.path or "%2e%2e" in flow.url.lower():
        return {"drop": True, "reason": "path traversal in URL"}
    return False
```

### 9. Rewrite a request body

A Blocking filter can mutate the message before Janus forwards it. Assign
`flow.body` (text) or `flow.content` (bytes).

```python
def match(flow):
    if "debug=1" in flow.body:
        flow.body = flow.body.replace("debug=1", "debug=0")   # neuter a debug flag
        return "stripped debug flag from request"
    return False
```

### 10. Second login onward (stateful, SNAT-safe)

Under SNAT every team shares one source IP, so **never key on IP**. Key on a
request field — here the credential. Module-level state persists across calls.

```python
attempts = {}

def match(flow):
    if flow.method == "POST" and flow.path.endswith("/login"):
        user = (flow.json() or {}).get("user")
        if user:
            attempts[user] = attempts.get(user, 0) + 1
            if attempts[user] > 1:
                return "repeated login for %s (#%d)" % (user, attempts[user])
    return False
```

### 11. Login reusing a registered password

Collect passwords seen at `/register`, then flag a `/login` that reuses one while
carrying a flag-ID (a classic account-takeover shape). Mark **Blocking** to drop.

```python
registered = set()

def match(flow):
    if flow.method != "POST":
        return False
    pw = (flow.json() or {}).get("password", "")
    if not pw:
        return False
    if flow.path.endswith("/register"):
        registered.add(pw)
    elif flow.path.endswith("/login") and flow.contains_flagid and pw in registered:
        return {"drop": True, "reason": "login flag-ID with a registered password"}
    return False
```

### 12. Correlate request → response

From a response you can look back at its request (never `None`). Alert on a flag
in a response to a route that wasn't authenticated.

```python
DIRECTION = "response"

def match(flow):
    if flow.flagged and flow.request.header("authorization") == "":
        return "flag returned to an unauthenticated %s" % flow.request.path
    return False
```

---

## TCP / byte streams

TCP services are a continuous byte flow. `flow.lines` reassembles complete lines
across chunks; `flow.conn` is per-connection scratch; `flow.commands(spec)` parses
a line-based CLI for you.

### 13. Alert when a chunk carries a flag

```python
def match(flow):
    if flow.flagged:
        return "flag seen on the %s side" % flow.direction
    return False
```

### 14. Block a raw command by content

No parsing — just look at the bytes of this chunk.

```python
def match(flow):
    if b"DROP TABLE" in flow.content or b"/bin/sh" in flow.content:
        return {"drop": True, "reason": "dangerous payload in stream"}
    return False
```

### 15. Parse a line protocol by hand

`flow.lines` hands you complete lines (bytes), buffering partial ones across
chunks — you never manage a byte buffer.

```python
DIRECTION = "request"

def match(flow):
    for line in flow.lines:
        if line.upper().startswith(b"AUTH ") and flow.contains_flagid:
            return "AUTH with a flag-ID: %r" % line
    return False
```

### 16. Parse a CLI menu with flow.commands

`spec` maps a trigger line to `(name, field-names)`. Read arguments **by name** —
don't unpack `cmd.args`, since different commands can have different arities.

```python
DIRECTION = "request"
CMDS = {
    b"1": ("register", ("user", "pw")),   # "1\n" then two lines
    b"2": ("login",    ("user", "pw")),
}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "register":
            flow.conn.setdefault("regs", set()).add(cmd.pw)
        elif cmd.name == "login" and cmd.flagid and cmd.pw in flow.conn.get("regs", set()):
            return {"drop": True, "reason": "login as flag-ID reusing a registered password"}
    return False
```

### 17. Block "get vip" on a flag-ID flight

The menu item that leaks the flag is `6` (`Get vip of private flight`). Drop the
request that asks for a vip whose flight number is one of our flag-IDs.

```python
DIRECTION = "request"
CMDS = {b"6": ("getvip", ("flight",))}    # "6\n" then the flight number

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "getvip" and cmd.flagid:
            return {"drop": True, "reason": "get-vip on a flag-ID flight (flag theft)"}
    return False
```

### 18. Only the owner may read the vip (auth tracking)

Blocking example 17 outright can hit the checker, which legitimately reads its own
flag-ID vip. Distinguish attacker from checker: the attacker uses a *throwaway*
(non-flag-ID) account, the checker authenticates as the flag-ID owner. Track it on
`flow.conn`.

```python
DIRECTION = "request"
CMDS = {
    b"1": ("register", ("user", "pw")),
    b"2": ("login",    ("user", "pw")),
    b"6": ("getvip",   ("flight",)),
}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name in ("register", "login") and not cmd.flagid:
            flow.conn["own_account"] = True        # used a throwaway identity
        elif cmd.name == "getvip" and cmd.flagid and flow.conn.get("own_account"):
            return {"drop": True, "reason": "get-vip on a flag-ID from a throwaway session"}
    return False
```

### 19. Second flag-ID login on a connection

Another attacker tell: they log into their own account first, then try to log in
*as the victim* (a flag-ID username). The checker logs in once, as the owner. So
"the 2nd+ login on this connection uses a flag-ID" is attacker-shaped.

```python
DIRECTION = "request"
CMDS = {b"2": ("login", ("user", "pw"))}

def match(flow):
    for cmd in flow.commands(CMDS):
        n = flow.conn.get("logins", 0) + 1
        flow.conn["logins"] = n
        if n >= 2 and cmd.flagid:
            return {"drop": True, "reason": "2nd login on this connection targets a flag-ID"}
    return False
```

### 20. Redact a flag from a TCP response

Instead of dropping the connection, rewrite the response so the client gets a
plausible-looking blank instead of the flag. Response rewriting is inline for TCP
and needs **Blocking**.

```python
import re
DIRECTION = "response"
FLAG = re.compile(rb"[A-Z0-9]{31}=")     # match your flag format

def match(flow):
    if FLAG.search(flow.content):
        flow.content = FLAG.sub(b"X" * 31 + b"=", flow.content)
        return "redacted a flag from the response"
    return False
```

### 21. Password reuse across connections

`flow.conn` is per-connection; for state that spans connections use a module-level
container. Here: notice the same password registered from many separate sessions.

```python
DIRECTION = "request"
CMDS = {b"1": ("register", ("user", "pw"))}
seen = {}

def match(flow):
    for cmd in flow.commands(CMDS):
        seen[cmd.pw] = seen.get(cmd.pw, 0) + 1
        if seen[cmd.pw] == 5:
            return "password %r registered from many sessions" % cmd.pw
    return False
```

### 22. Length-prefixed binary framing

For binary protocols, buffer raw bytes on `flow.conn` yourself and parse frames.
Here: a 4-byte big-endian length, then that many bytes; alert if a frame body
holds a flag-ID.

```python
DIRECTION = "request"

def match(flow):
    buf = flow.conn.get("buf", b"") + flow.content
    hits = []
    while len(buf) >= 4:
        n = int.from_bytes(buf[:4], "big")
        if len(buf) < 4 + n:
            break                                    # frame not complete yet
        frame, buf = buf[4:4 + n], buf[4 + n:]
        if flow.contains_flagid and frame:
            hits.append(len(frame))
    flow.conn["buf"] = buf[-65536:]                  # keep the remainder, capped
    if hits:
        return "flag-ID inside framed payload(s): %r" % hits
    return False
```

---

## Testing your filter

Use the **Test** panel on the Python Filters page before enabling anything: build
a Request/Response sample, or load a real captured packet (or a whole
request+response **flow**) from traffic. Whole-flow tests replay `match()` over
the packets in order, so stateful and `flow.commands`-based scripts see the real
sequence, and each step shows an **Alert** / **Alert + Block** verdict. The
`Repeat` control re-runs the sample so counting logic (e.g. "2nd login") fires.
