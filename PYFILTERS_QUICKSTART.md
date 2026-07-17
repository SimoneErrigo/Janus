# PyFilters: quick start

PyFilters are small Python functions run by Janus for captured traffic. Use a
PyFilter when a normal rule in [FILTERS.md](FILTERS.md) is not enough: for
example when a decision depends on a JSON field, a previous request, or a TCP
command sequence.

This page keeps the examples intentionally small. For every accessor and the
full runtime contract, see [PYFILTERS.md](PYFILTERS.md); for advanced A/D
recipes, see [PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md).

## Create and test a filter

1. Open **PyFilters**, choose a small template (or start blank), and edit its
   `match(flow)` function. The snippet buttons insert common fields and actions.
2. Select at least one service; optionally narrow direction and protocol.
3. Start in **Observe**; promote to **Inline** only after the dry-run is clean.
4. Test it with a manual sample, a captured packet ID, or a complete flow loaded
   server-side from one packet ID. The selected mode and scope also apply to the
   test. Manual samples are scanned with the configured flag pattern, so flag
   counters behave like captured traffic.
5. Save and enable it. New filters start disabled and must pass a test first.

Every script runs independently and its module-level variables persist until the
script is reloaded. A missing field is safe: `flow.path`,
`flow.headers["x"]`, and `flow.query["id"]` return an empty value rather than
raising an exception.

## Choose the execution mode

| Type | What it does | Can it change live traffic? |
| --- | --- | --- |
| Observe (default) | Evaluates after capture and creates alerts. | No. The message has already been forwarded. |
| Inline | Evaluates synchronously on the scoped proxy path. | Yes. The script may drop, close, or rewrite the current message. |

Inline filters work in both directions for TCP, UDP, and WebSocket. Ordinary
HTTP/HTTPS responses can also be blocked or rewritten while they fit in the
1 MiB response buffer. Flushed/streaming/oversized responses and HTTP/2 or gRPC
responses are observe-only.

For a body-based HTTP request decision, first check `flow.body_complete`.
Unknown-length/chunked streams are not pre-read (that could stall the service),
and bodies over 1 MiB expose only a prefix inline. Metadata is still usable;
Observe sees the captured prefix after forwarding.

```python
if flow.is_request and flow.body_complete and b"exploit" in flow.content:
    return flow.drop("known exploit marker")
```

For every message, use `flow.is_request` or `flow.is_response`. A module-level
`DIRECTION = "request"` or `DIRECTION = "response"` saves Janus from invoking a
script on the other direction.

## 1. Alert on a suspicious path

This is an **Observe** filter. It does not block anything; it creates an alert
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

Mark this filter **Inline**. The example only applies to `/download`, so it
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
request with no JSON body. Mark it **Inline** only if the match must stop the
request; otherwise the same code can be used as an Observe alert.

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

`flow.state` keeps bounded, private state for this filter and connection. This
**Observe** example alerts only on the second and later login for the same user
within 30 seconds. In the test panel set **Repeat** to `2` to see the alert.

```python
DIRECTION = "request"

def match(flow):
    if flow.method != "POST" or flow.path != "/login":
        return False

    user = (flow.json() or {}).get("user", "")
    if not user:
        return False

    count = flow.state.count("login", key=user, window=30)
    if count > 1:
        return "repeated login for %s (#%d)" % (user, count)
    return False
```

`flow.state` is per Janus connection/session. If a detector intentionally spans
different connections, use a bounded module-level dictionary keyed by a session
cookie, credential, or another request field—not only the peer IP, which may be
shared behind SNAT.

## 5. Count outgoing flags

The current message has detailed flag counts; the connection counters contain
only earlier traffic that Janus admitted. Adding the two therefore does not
double-count the current response.

```python
DIRECTION = "response"

def match(flow):
    total = flow.connection.flags_out + flow.flags.count
    if total >= 3:
        return flow.drop("third outgoing flag on this connection")
    return False
```

Use `flow.flags.body_count`, `header_count`, `url_count`, `known_count`, and
`matched_ids` when the distinction matters. This example needs **Inline** mode
to stop traffic; start in Observe while tuning the threshold.

## 6. Fingerprint a short connection burst

Connection age, idle time, counts, rates, and a deterministic payload-free
shape fingerprint are ready to use. No AI or training is involved.

```python
def match(flow):
    c = flow.connection
    if c.age_ms < 1500 and c.rate_in(1) >= 20:
        return flow.close("fast burst on a new connection")
    return False
```

`flow.connection.fingerprint()` describes recent direction, coarse size/timing,
protocol, and decoded hints. Store it with `flow.state.seen(...)` when a service
needs a repeated-sequence detector.

## 7. Read complete lines from a TCP service

TCP payloads can arrive split across arbitrary chunks. `flow.lines` yields only
new complete lines, so no manual byte buffer is necessary. This example is an
**Observe** alert for a line-based CLI service.

```python
DIRECTION = "request"

def match(flow):
    for line in flow.lines:
        if line == b"DEBUG":
            return "debug command in TCP stream"
    return False
```

For multi-line commands use `flow.commands(...)`; for data that belongs to one
connection use `flow.state`. `flow.conn` remains a legacy alias. Both are
covered in the [full reference](PYFILTERS.md#tcp-line-and-command-helpers).

For WebSocket services, Janus calls the filter once per complete, decoded text
or binary message. An Inline drop removes only that message and keeps the
session open; `flow.body` and `flow.content` rewrites work in both directions.

## Return values at a glance

| Return from `match(flow)` | Result |
| --- | --- |
| `False` or `None` | Ignore the message. |
| `True` | Alert without a reason. |
| `"reason"` | Alert with a reason. |
| `{"match": True, "reason": "..."}` | Explicit alert. |
| `{"drop": True, "reason": "..."}` | Alert and request an inline block; requires **Inline**. |

The equivalent helpers are `flow.alert(reason)`, `flow.drop(reason)`,
`flow.close(reason)`, and `flow.rewrite(content, reason="")`.

In an Inline filter, assigning `flow.body = "..."` rewrites text and
assigning `flow.content = b"..."` rewrites exact bytes. Use rewriting narrowly
and test it against a real flow before relying on it during a match.
