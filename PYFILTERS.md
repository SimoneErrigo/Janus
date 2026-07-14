# Python filters — reference

A PyFilter is a small Python function named `match(flow)`. Janus calls it once
for each HTTP message, TCP chunk, UDP datagram, or complete WebSocket message.
The same forgiving object is used everywhere: a missing protocol-specific field
returns an empty value instead of crashing the script.

New to PyFilters? Start with [PYFILTERS_QUICKSTART.md](PYFILTERS_QUICKSTART.md).
For fuller A/D recipes, use [PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md).

```python
def match(flow):
    if flow.path == "/admin":
        return flow.drop("admin endpoint")
    return False
```

## Modes and protocol limits

Select services, directions, and protocols in the editor before enabling a
script. A module-level `DIRECTION = "request"` or `"response"` is an optional
second guard.

| Mode in the UI | Execution | Live effect |
| --- | --- | --- |
| **Observe** (default) | asynchronous, after capture | alert only |
| **Inline** | synchronous, before forwarding | alert, drop, close, or replace the current body |

| Traffic | Observe | Inline |
| --- | --- | --- |
| HTTP/1.1 and HTTPS requests with a known body up to 1 MiB | yes | yes |
| Chunked/unknown-length or larger HTTP request bodies | yes, full captured prefix after forwarding | metadata inline; incomplete body cannot be rewritten |
| Ordinary HTTP/1.1 and HTTPS responses | yes | yes, while the complete response fits in the 1 MiB buffer |
| Flushed/streaming or larger HTTP responses | yes | observe-only after streaming/overflow begins |
| HTTP/2 and gRPC requests | yes | metadata inline; streamed body is not pre-read |
| HTTP/2 and gRPC responses | yes | observe-only |
| TCP, TCP-line, TLS, RESP, MQTT, DNS-over-TCP, custom TCP | yes | both directions |
| UDP and DNS | yes | both datagram directions |
| WS and WSS | yes | both message directions |

Janus buffers an ordinary HTTP response only when an enabled response-scoped
inline script could use it. `Flush`, streaming, or crossing 1 MiB switches to
forwarding without an inline drop/rewrite. This bounded fail-open behaviour
avoids turning a filter into a service stall. A tester result validates the
script but cannot turn an observe-only protocol path into an inline one.

Enabled Inline scripts are compiled and prewarmed before a service starts and
after script changes. Worker creation never runs on the traffic hot path: a
missing, stale, or failed worker lets that message pass and is rebuilt in the
background. This keeps filter administration from causing a first-packet stall.

For request bodies, Janus never waits for EOF on an unknown-length/chunked
stream: doing so could stall the service. The inline call therefore receives an
empty or bounded prefix with `flow.body_complete == False` and
`flow.truncated == True`; metadata filters still work, while body-based filters
should return without dropping or rewriting. The captured prefix becomes
available to Observe filters after the backend has consumed the stream. A
known-length body larger than 1 MiB is handled the same way, except that its
first 1 MiB is already visible inline. This is intentionally fail-open.

## Verdicts and action helpers

| Return from `match(flow)` | Result |
| --- | --- |
| `False` / `None` | no match |
| `True` | alert without a reason |
| `"reason"` | alert with a reason |
| `{"match": True, "reason": "..."}` | explicit alert |
| `{"drop": True, "reason": "..."}` | drop the current message in Inline mode |

The helpers make the common cases easier to read:

```python
return flow.alert("unusual but allowed")
return flow.drop("known exploit")
return flow.close("stop this connection")
return flow.rewrite(flow.content.replace(b"bad", b"safe"), "sanitized")
```

`flow.close()` also drops the current message and closes HTTP, TCP, or WebSocket
connection/session state. On UDP there is no persistent transport connection to
close. Assigning `flow.body` or `flow.content` directly is also a rewrite; only
Inline mode forwards the replacement.

## Current message

| Accessor | Meaning |
| --- | --- |
| `flow.service`, `flow.session`, `flow.protocol` | selected service, Janus connection/session, protocol preset |
| `flow.direction`, `flow.is_request`, `flow.is_response` | `request` / `response` and boolean shortcuts |
| `flow.src`, `flow.dst`, `flow.sport`, `flow.dport` | endpoints |
| `flow.size` | exact message size when known |
| `flow.body` | forgiving text view; settable |
| `flow.content` / `flow.bytes` | exact bytes; settable |
| `flow.body_complete` / `flow.truncated` | whether the whole current body is visible; require completeness before body-based inline actions |
| `flow.json(default=None)` | parsed JSON body or the supplied default |
| `flow.decoded` | decoded protocol fields, or an empty value |
| `flow["x"]`, `flow.get("x")` | raw dictionary access remains supported |

HTTP adds `flow.method`, `flow.url`, `flow.path`, `flow.status`,
case-insensitive `flow.headers` / `flow.header(name)`, `flow.query`, and
`flow.cookies`. For example, repeated parameters are available through
`flow.query.all("id")`.

For WebSocket, Janus evaluates one reassembled text or binary message rather
than individual frames. `flow.method == "WS"`, `flow.url` is the upgrade URL,
and `flow.headers["X-Janus-WebSocket-Opcode"]` is `text` or `binary`.
Dropping one message normally leaves the session alive; use `flow.close()` when
the whole WebSocket should end. Messages larger than 1 MiB are rejected before
forwarding.

## Flags in the current message

`flow.flagged` and `flow.contains_flagid` remain simple booleans. Use
`flow.flags` when a filter needs counts or the matched known IDs:

| Accessor | Meaning |
| --- | --- |
| `flow.flags.count` | all flag-pattern matches in the current message |
| `flow.flags.known_count` | known Flag ID matches in the current message |
| `flow.flags.body_count` | flag matches in the body |
| `flow.flags.header_count` | flag matches in headers |
| `flow.flags.url_count` | flag matches in the URL |
| `flow.flags.matched_ids` | tuple of matched known Flag ID values |

Old imported rows that stored only `flagged=true` expose the safe lower bound
`count=1` and `body_count=1`; new captures persist exact component counts.

Component counts make direction-aware filters simple. For example, count
already-admitted output flags plus the current response before deciding it:

```python
def match(flow):
    if flow.is_response and flow.connection.flags_out + flow.flags.count >= 3:
        return flow.drop("too many outgoing flags")
    return False
```

The dashboard dry-run scans synthetic URL, headers, and body with the active
Janus flag pattern automatically. You can therefore paste a realistic payload
without calculating hidden `flag_count_*` fields yourself.

## Connection measurements and fingerprint

`flow.connection` is read-only metadata shared by every filter view of the same
Janus connection/session.

| Accessor | Meaning before the current decision |
| --- | --- |
| `id`, `age_ms`, `idle_ms` | connection identity, lifetime, and time since the previous message |
| `messages`, `messages_in`, `messages_out` | admitted message counts |
| `bytes_in`, `bytes_out` | admitted byte counts |
| `flags_in`, `flags_out` | admitted flag-pattern counts |
| `known_flags_in`, `known_flags_out` | admitted known Flag ID counts |
| `rate_in(seconds=2)`, `rate_out(seconds=2)` | admitted messages per second in a bounded window |
| `recent`, `current` | bounded previous shapes and the current payload-free shape |
| `fingerprint()` | stable 16-character shape fingerprint of recent admitted traffic plus the current message |

The **current message is deliberately excluded** from every counter and rate,
so an expression can safely add `flow.flags.count` once. A dropped or otherwise
unadmitted message is not committed later. `fingerprint()` uses direction,
coarse size/gap buckets, protocol, and a decoded-field hint—not payload bytes,
secrets, or AI. When an Inline rewrite is applied, Janus reconciles these
counters with the forwarded replacement before the next message is evaluated.

```python
def match(flow):
    c = flow.connection
    if c.age_ms < 1500 and c.rate_in(1) >= 20:
        return flow.close("new connection burst")
    return False
```

## Bounded state

`flow.state` is private to this filter and connection/session. It behaves like a
dictionary, is automatically bounded, and expires with idle connection state.
Use it instead of unbounded module globals for connection fingerprinting.
`flow.conn` is kept as a legacy alias for `flow.state`.

```python
def match(flow):
    attempts = flow.state.count("login", key=flow.path, window=10)
    if attempts > 8:
        return flow.drop("login burst")
    return False
```

| Helper | Records, then returns |
| --- | --- |
| `count(name, key="", window=10, amount=1)` | weighted event count inside the time window |
| `seen(name, value="", ttl=300)` | whether the value was already seen within the TTL |
| `distinct(name, value, key="", window=60)` | number of distinct recent values |
| `observe(name, value, key="", window=60)` | numeric statistics: `count`, `mean`, `median`, `mad`, `p95`, `min`, `max` |

History is also connection/session-local and bounded to the most recent 32
messages (2,048 entries globally); it is never mixed across clients of the same
service. Historical bodies keep a 16 KiB prefix and set `history_truncated` when
the original was larger:

| Accessor | Meaning |
| --- | --- |
| `flow.messages`, `flow.recent(n=3)` | history with the current message last |
| `flow.requests`, `flow.responses` | history filtered by direction |
| `flow.last_request`, `flow.last_response` | previous message of that direction |
| `flow.request`, `flow.response` | current side or the correlated previous other side; never `None` |

For application state that deliberately spans transport connections, a
module-level dictionary keyed by a cookie or credential is still possible. Keep
it bounded yourself; never use only an IP because competition traffic may share
SNAT.

## TCP line and command helpers

TCP chunks are arbitrary. `flow.lines` returns only complete new lines as
`bytes` and preserves a partial tail for the next chunk. `flow.commands(spec)`
parses a line-oriented command plus its following argument lines:

```python
CMDS = {
    b"1": ("register", ("user", "pw")),
    b"2": ("login", 2),
}

def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "login" and cmd.flagid:
            return flow.drop("login contains a Flag ID")
    return False
```

Named arguments are available as `cmd.user`; positional arguments use
`cmd.arg(0)`. Missing arguments read as `b""`. Empty argument lines are valid
and preserved. Do not unpack `cmd.args` when a table mixes command arities.

## Test before enabling

The **PyFilters** page separates writing, scope, and testing:

1. Start from a template or insert a field/action snippet.
2. Choose Observe or Inline and select service, direction, and protocol.
3. Test a manual sample, enter a captured packet ID, or enter one packet ID and
   load its complete reconstructed flow from the server.
4. Use **Repeat** for counters and stateful sequences, then test the checker
   happy path too.

Server-loaded samples retain exact body bytes, timestamp, protocol, session,
and direction. Tests apply the selected mode and scope and report one verdict
per sequence step, including console output, alert/drop/close requests, and a
best-effort rewritten body. Saving/enabling is still required for a live effect.

The HTTP API accepts the same inputs as `flow`, `flows`, `packet_id`, or
`flow_packet_id`; see [API.md](API.md#pyfilters).

## Analysis helpers (`util`)

`util` is injected into every script. The most useful helpers are:

| Helper | Meaning |
| --- | --- |
| `is_base64`, `b64`, `valid_json`, `extra_keys` | validate structured input |
| `entropy`, `longest_run`, `repeated_block`, `printable_ratio` | characterize payload bytes |
| `magic`, `content_type_ok`, `trailing_data`, `qr_decode` | inspect uploads |
| `text_layers`, `find_payload`, `scan`, `strings`, `inspect` | search raw and embedded text layers |
| `normpath`, `uri_scheme`, `path_escapes`, `has_control_chars` | normalize paths and validate text |

Exact signatures and arguments are demonstrated in
[PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md).
