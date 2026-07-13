# PyFilters: quick start

PyFilters are small Python functions run by Janus for captured traffic. Use a
PyFilter when a normal rule in [FILTERS.md](FILTERS.md) is not enough: for
example when a decision depends on a JSON field, a previous request, or a TCP
command sequence.

This page keeps the examples intentionally small. For every accessor and the
full runtime contract, see [PYFILTERS.md](PYFILTERS.md); for advanced A/D
recipes, see [PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md).

## Create and test a filter

1. Open **PyFilters**, give the script a name, and paste a `match(flow)`
   function.
2. Test it with the built-in sample, a captured packet, or **Load flow**.
3. Leave **Blocking** off when the filter only needs to alert.
4. Enable **Blocking** only when the script must stop or rewrite the current
   traffic message. Test the exact checker flow first.
5. Enable the script.

Every script runs independently and its module-level variables persist until the
script is reloaded. A missing field is safe: `flow.path`,
`flow.headers["x"]`, and `flow.query["id"]` return an empty value rather than
raising an exception.

## Choose the execution mode

| Type | What it does | Can it change live traffic? |
| --- | --- | --- |
| Async (default) | Evaluates after capture and creates alerts. | No. The message has already been forwarded. |
| Blocking | Evaluates synchronously on the proxy path. | Yes. HTTP requests, plus TCP and WebSocket requests and responses, can be dropped or rewritten. |

For every message, use `flow.is_request` or `flow.is_response`. A module-level
`DIRECTION = "request"` or `DIRECTION = "response"` saves Janus from invoking a
script on the other direction.

## 1. Alert on a suspicious path

This is an **async** filter. It does not block anything; it creates an alert
when a request targets `/admin`.

```python
DIRECTION = "request"

def match(flow):
    if flow.path.startswith("/admin"):
        return "request to an admin path"
    return False
```

`flow.path` contains only the URL path. Use `flow.url` when query parameters
matter too.

## 2. Block an unexpected query parameter

Mark this filter **Blocking**. The example only applies to `/download`, so it
does not accidentally inspect unrelated endpoints.

```python
DIRECTION = "request"

def match(flow):
    if flow.path == "/download" and flow.query["debug"] == "1":
        return {"drop": True, "reason": "debug download is not allowed"}
    return False
```

`{"drop": True}` blocks the **current** request before it reaches the service.
`"block"` is an alias for `"drop"`.

## 3. Inspect a JSON field

`flow.json()` returns the parsed body or `None`, which makes this safe for a
request with no JSON body. Mark it **Blocking** only if the match must stop the
request; otherwise the same code can be used as an async alert.

```python
DIRECTION = "request"
ALLOWED = {"small", "medium", "large"}

def match(flow):
    if flow.method != "POST" or flow.path != "/export":
        return False

    size = (flow.json() or {}).get("size", "")
    if size and size not in ALLOWED:
        return {"drop": True, "reason": "unknown export size: %s" % size}
    return False
```

Useful HTTP fields are `flow.method`, `flow.path`, `flow.status`,
`flow.headers["Content-Type"]`, `flow.query["name"]`, and
`flow.cookies["session"]`.

## 4. Count a repeated action

Module globals keep their value between messages. This **async** example alerts
only on the second and later login for the same user. In the test panel set
**Repeat** to `2` to observe the first alert.

```python
DIRECTION = "request"
logins = {}

def match(flow):
    if flow.method != "POST" or flow.path != "/login":
        return False

    user = (flow.json() or {}).get("user", "")
    if not user:
        return False

    logins[user] = logins.get(user, 0) + 1
    if logins[user] > 1:
        return "repeated login for %s (#%d)" % (user, logins[user])
    return False
```

For HTTP correlation across different connections, key state by a session
cookie, credential, or another request field — not just the peer IP, which may
be shared by opponents behind SNAT.

## 5. Read complete lines from a TCP service

TCP payloads can arrive split across arbitrary chunks. `flow.lines` yields only
new complete lines, so no manual byte buffer is necessary. This example is an
**async** alert for a line-based CLI service.

```python
DIRECTION = "request"

def match(flow):
    for line in flow.lines:
        if line == b"DEBUG":
            return "debug command in TCP stream"
    return False
```

For multi-line commands use `flow.commands(...)`; for data that belongs to one
TCP connection use `flow.conn`. Both are covered in the
[full reference](PYFILTERS.md#tcp-streams-a-continuous-byte-flow-not-one-message-per-chunk).

For WebSocket services, Janus calls the filter once per complete, decoded text
or binary message. A Blocking drop removes only that message and keeps the
session open; `flow.body` and `flow.content` rewrites work in both directions.

## Return values at a glance

| Return from `match(flow)` | Result |
| --- | --- |
| `False` or `None` | Ignore the message. |
| `True` | Alert without a reason. |
| `"reason"` | Alert with a reason. |
| `{"match": True, "reason": "..."}` | Explicit alert. |
| `{"drop": True, "reason": "..."}` | Alert and request an inline block; requires **Blocking**. |

In a Blocking filter, assigning `flow.body = "..."` rewrites text and
assigning `flow.content = b"..."` rewrites exact bytes. Use rewriting narrowly
and test it against a real flow before relying on it during a match.
