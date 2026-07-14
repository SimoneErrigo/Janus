# Janus API

REST reference for the Janus backend. See [README.md](README.md) for operating
Janus and [FILTERS.md](FILTERS.md) for the filter-expression language.

## Access and authentication

With Docker Compose, the frontend proxies requests to the backend. Use
`http://localhost:2999/api` or the relative path `/api`. The normal Compose
stack does not need to publish the backend separately.

Every route except `POST /api/login` requires either the same-origin
`janus_session` cookie set at login or, for non-browser clients:

```http
Authorization: Bearer <token>
```

Tokens are deliberately not accepted in query strings. This keeps SSE and
download credentials out of browser history, proxy logs, and copied links.
Requests and responses are JSON unless the route explicitly handles PCAP data
or multipart upload. Validation errors use HTTP 400; a missing resource uses
HTTP 404.

### Login

```http
POST /api/login
Content-Type: application/json

{"password":"...","display_name":"analyst"}
```

The response returns a Bearer token for API clients and also installs an
HttpOnly session cookie for the dashboard. `display_name` is used only for the
presence indicator in the dashboard.

## Routes

| Area | Method | Route | Purpose |
| --- | --- | --- | --- |
| Session | GET | `/api/session/active` | Online users (heartbeat-based) |
| Services | GET, POST | `/api/services` | List or create a service |
|  | GET | `/api/protocol-presets` | Beginner protocol choices and generated runtime specs |
|  | GET, PUT, DELETE | `/api/services/{id}` | Read, update, or delete a service |
|  | POST | `/api/services/{id}/retry` | Immediately retry a listener bind |
|  | GET | `/api/proxy/statuses` | Listener status and latest bind error |
|  | POST | `/api/proxy/retry-all` | Retry every listener currently retrying |
| Traffic | GET | `/api/packets` | Query packets (`q`, `sort`, `limit`, `offset`, opaque `cursor`) |
|  | GET, DELETE | `/api/packets/{id}` | Read or remove one packet |
|  | POST | `/api/packets/bulk-delete` | Remove a list of packet IDs |
|  | POST | `/api/packets/label` | Annotate packet IDs as exploit, checker, or normal |
|  | GET | `/api/packets/stream` | SSE packet, score-patch and metadata stream |
|  | GET | `/api/packets/flow?packet_id=N` | Reconstruct a packet flow |
|  | GET | `/api/packets/flow/pcap?packet_id=N` | Download a flow as PCAP |
|  | GET | `/api/packets/exploit?packet_id=N` | Generate a Python exploit skeleton |
|  | GET | `/api/packets/decoded?packet_id=N` | Decode a protobuf/gRPC body |
|  | GET | `/api/packets/decoded-custom?packet_id=N[&protocol_id=P]` | Decode with a custom protocol |
| Rules | GET, POST | `/api/rules` | List or create rules |
|  | GET, PUT, DELETE | `/api/rules/{id}` | Read, update, or delete a rule |
|  | GET | `/api/rules/{id}/revisions` | List immutable rule revisions |
|  | POST | `/api/rules/{id}/rollback` | Activate an old snapshot as a new revision |
|  | POST | `/api/rules/bulk-delete` | Remove rules by ID |
|  | GET | `/api/rules/presets` | List attack-preset categories |
|  | POST | `/api/rules/presets/apply` | Apply selected presets to services |
|  | POST | `/api/filter/validate` | Validate a filter expression |
|  | GET | `/api/filter/schema` | Queryable fields, patterns, and valid operators |
| Scoring | GET | `/api/scoring/status` | Opening-baseline progress and classification counts |
|  | POST | `/api/scoring/baseline/rebuild` | Rebuild the selected opening baseline from retained traffic |
| Alerts | GET, DELETE | `/api/alerts` | List or clear alerts |
|  | GET | `/api/alerts/{id}` | Read alert detail |
| PyFilters | GET, POST | `/api/pyfilters` | List scripts and engine status, or create a script |
|  | GET, PUT, DELETE | `/api/pyfilters/{id}` | Read, update, or delete a script |
|  | GET | `/api/pyfilter-engine/status` | Python runtime health |
|  | POST | `/api/pyfilter-engine/test` | Test a script against a packet or flow |
| Protocols | GET, POST | `/api/protocols` | List or create a custom binary decoder |
|  | GET, PUT, DELETE | `/api/protocols/{id}` | Read, update, or delete a decoder |
|  | POST | `/api/protocols/import` | Build a decoder draft from Python source |
|  | GET | `/api/protos` | List `.proto` files under `PROTO_DIR` |
|  | POST | `/api/protos/encode-field` | Encode a protobuf field value from JSON |
| Flag IDs | GET | `/api/flagids` | Current `service -> values` map |
|  | GET | `/api/flagids/status` | Poller status, round, and latest error |
|  | POST | `/api/flagids/refresh` | Fetch now; live-mode backfill follows |
| Capture | GET | `/api/traffic/capture` | Static-capture status |
|  | POST | `/api/traffic/capture/start` | Start a capture window |
|  | POST | `/api/traffic/capture/stop` | Stop the current capture |
|  | POST | `/api/traffic/capture/apply-flagids` | Re-scan captured packets for Flag IDs |
| Saved flows | GET, POST | `/api/flows/saved` | List or save a flow/selection |
|  | GET, DELETE | `/api/flows/saved/{id}` | Read or delete a snapshot |
| Round Diff | GET | `/api/round-diff` | Compare two rounds for one service |
| PCAP | POST | `/api/pcap/export` | Export packets matching a filter |
|  | POST | `/api/pcap/export-selection` | Export explicit packet IDs |
|  | GET | `/api/pcap/files` | List available PCAP files |
|  | GET, DELETE | `/api/pcap/files/{name}` | Download or delete a PCAP |
|  | POST | `/api/pcap/import` | Upload a PCAP as multipart data |
|  | GET | `/api/pcap/import/{id}` | Asynchronous import status |
| Configuration | GET, PUT | `/api/config` | Read or update runtime configuration |
|  | GET, PUT | `/api/config/cleanup` | Read or update cleanup policy |
|  | POST | `/api/cleanup/run` | Run cleanup now |
|  | POST | `/api/cleanup/purge` | Delete packets and alerts |
|  | POST | `/api/cleanup/purge-packets` | Delete packets only |
|  | POST | `/api/cleanup/purge-dropped` | Delete dropped packets only |
| System | GET | `/api/system/stats` | CPU, RAM, disk, database, and Redis metrics |

## Main payloads

### Service

`POST /api/services` accepts the following fields. Janus derives `id` from
`name` when it is omitted.

```json
{
  "name": "Web challenge",
  "listen_addr": "10.10.0.1",
  "listen_port": 8080,
  "target_addr": "127.0.0.1:9080",
  "protocol": "http",
  "enabled": true
}
```

`protocol` is one of `http`, `https`, `ws`, `wss`, `h2`, `h2c`, `grpc`,
`grpc-h2c`, `tcp`, `tcp-line`, `tls`, `udp`, `dns`, `dns-tcp`, `resp`, or
`mqtt`. The UI obtains this list from `GET /api/protocol-presets`.
It is the only architectural choice required from the user. Janus returns a
generated `spec` containing `listener`, `application`, `upstream`, and
`framing`, plus `model_version`; clients should treat these fields as
read-only preset output. Legacy service records are migrated automatically.
WebSocket services use `ws` for a cleartext listener and `wss` for a TLS
listener. TLS fields are
`tls_mode` (`selfsigned` or `challenge`), `cert_file`, `key_file`, and
`target_tls`. A gRPC service can set `proto_paths`; a TCP service can set
`protocol_id` to bind a custom decoder.

Captured WebSocket application messages use method `WS`, retain the handshake
URL and session ID, and expose their decoded payload in `body`/`body_string`.
`X-Janus-WebSocket-Opcode` identifies `text` or `binary` messages. Rules are
evaluated on complete, unmasked client messages before forwarding. Inline
PyFilters also run on backend responses and may drop or rewrite the current
message without closing the WebSocket. Subprotocol headers are preserved;
WebSocket extensions are disabled so filtering always sees the clear
application payload. Messages larger than 1 MiB are dropped and recorded with
the synthetic rule `janus:websocket-message-limit`.

### Rules and packet search

The `pattern` field of a rule and the `q` parameter of packet/alert searches
share the same DSL. For example:

```text
method == "POST" AND url contains "/login" AND body matches "(?i)union"
```

See [FILTERS.md](FILTERS.md) for the complete language. Legacy packet search
parameters (`contains`, `regex`, `src_ip`, ...) remain available.

Successful `POST /api/filter/validate` responses also include `fields` and
`server_required`. The latter is true when browser-side evaluation cannot be
guaranteed equivalent to the backend.

Captured packets include `verdict` (`decision`, `outcome`, `phase`, `applied`,
and matching rule IDs). `outcome=dropped` means bytes were actually stopped;
`would_drop` records a post-forward match. `capture_truncated=true` means only
the inspection copy was limited—the complete body was still forwarded.
The optional `classification`, attack/normal scores, coverage, confidence, and
reason ledger are deterministic shadow metadata; they never block traffic.
`analyst_label` is a manual annotation and does not train or directly change a
score. An `exploit` label excludes that flow the next time the opening baseline
is rebuilt.

### PyFilters

Create or replace a script with:

```json
{
  "name": "block-admin-post",
  "code": "def match(flow):\n    return False\n",
  "enabled": false,
  "mode": "observe",
  "service_ids": ["web"],
  "directions": ["request"],
  "protocols": ["http"]
}
```

`POST /api/pyfilter-engine/test` accepts `name`, `code`, and one of `flow`,
`flows` (an ordered sequence), `packet_id`, or `flow_packet_id`. `repeat`
replays the same sequence to exercise state. The optional `mode`,
`service_ids`, `directions`, and `protocols` use the same scope as a saved
script, so the tester also catches a sample excluded by its scope. Packet IDs
and flow packet IDs are resolved server-side and preserve the captured bytes,
timestamps, protocol, session, and direction.
For manual `flow`/`flows`, Janus scans URL, headers, and body with the current
configured flag matcher before the dry-run, so `flow.flags.*` has the same
meaning as it does on captured traffic. Explicit `flag_count_*` fields remain
available when a synthetic test needs to simulate metadata directly.
Each returned test step includes `rewritten`; when true, `rewrite_b64` contains
the exact replacement bytes (including binary payloads), while `rewrite` is a
best-effort text preview. This also represents an intentional empty rewrite
without confusing it with “no rewrite”.

The dashboard presents two choices, **Observe** and **Inline**. At REST level
`mode` accepts `observe`, `block`, or `rewrite` for backward compatibility;
both `block` and `rewrite` select the inline runtime, while the script's return
value decides whether it drops, closes, or rewrites.

Every protocol receives the same forgiving `flow` object. Important groups are:

- `flow.flags.count`, `known_count`, `body_count`, `header_count`, `url_count`,
  and `matched_ids` for the current message;
- `flow.connection` for read-only `age_ms`, `idle_ms`, message/byte/flag
  counters, `rate_in(seconds)`, `rate_out(seconds)`, `recent`/`current` shapes,
  and the payload-free `fingerprint()`;
- `flow.state` for bounded per-connection/per-script state and the
  `count`, `seen`, `distinct`, and `observe` window helpers (`flow.conn` remains
  as a legacy alias);
- `flow.alert()`, `flow.drop()`, `flow.close()`, and `flow.rewrite()` for clear
  verdicts.

Connection counters exclude the message currently being decided and count
only traffic already admitted by Janus. History and state are isolated by
connection/session rather than mixed across a service. Applied Inline rewrites
are reconciled synchronously, so the following message sees the forwarded size,
flags, and fingerprint rather than the original payload.

Inline actions work in both directions for TCP, UDP, WS, and WSS. They
also work for ordinary HTTP/1.1 and HTTPS responses while Janus can buffer the
complete response (up to 1 MiB). A flushed/streaming or oversized response is
forwarded and evaluated observe-only; HTTP/2 and gRPC responses are
observe-only. HTTP request flows expose `body_complete` and `truncated`:
unknown-length/chunked bodies are not pre-read, while known bodies over 1 MiB
expose only their prefix inline. Require `body_complete` before body-based
drop/rewrite logic; metadata remains available without delaying the service. See
[PYFILTERS.md](PYFILTERS.md) for the complete API and protocol table.

### Deterministic opening baseline

`GET /api/config` includes `baseline_start_round` and
`baseline_end_round`; `PUT /api/config` accepts either field. Both are
inclusive, must describe at least two and at most 50 rounds, and default to
rounds `1`–`5`:

```json
{
  "baseline_start_round": 1,
  "baseline_end_round": 5
}
```

Changing the range, competition start, or round duration rebuilds the baseline
from retained packets in that window. `POST /api/scoring/baseline/rebuild`
takes no body and forces the same replay for the current range; use it after
labelling contaminated flows as `exploit`.

`GET /api/scoring/status` returns `baseline_start_round`,
`baseline_end_round`, `baseline_required_rounds`, `rebuilding`,
`replayed_packets`, queue/storage errors, and per-service
observed/candidate/trusted counts plus the exact `complete` state. A
signature is trusted only if the same safe deterministic shape occurs in every
selected round. Truncated flows, rule/drop matches, suspicious payloads,
request flags/Flag IDs, and exploit-labelled flows are excluded. Thus an
otherwise distinct exploit signature seen in only one opening round is never
trusted.

This is static scoring, not AI. An exploit that is structurally identical to a
recurring checker flow, or an identical safe-looking exploit repeated in every
selected round, cannot be distinguished with certainty without external ground
truth. Choose a cleaner range or label it and rebuild when that happens.

### Round Diff

`GET /api/round-diff` requires `service_id`, `round_a` (baseline), and
`round_b` (round being analyzed). Optional `top_k` is `1..200` (default `24`);
`include_diff=true|false` controls inline field diffs. The response includes
stats, changed routes, suspicious packets, and URL/header/status/body changes.

## Operational notes

- Cleanup and delete routes are irreversible.
- In `static` mode, start and stop capture explicitly. Flag ID polling and
  automatic backfill are off.
- In `live` mode, a changed Flag ID fetch triggers automatic backfill of recent
  traffic. There is no separate automatic-backfill endpoint.
