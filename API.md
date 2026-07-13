# Janus API

REST reference for the Janus backend. See [README.md](README.md) for operating
Janus and [FILTERS.md](FILTERS.md) for the filter-expression language.

## Access and authentication

With Docker Compose, the frontend proxies requests to the backend. Use
`http://localhost:2999/api` or the relative path `/api`. The normal Compose
stack does not need to publish the backend separately.

Every route except `POST /api/login` requires:

```http
Authorization: Bearer <token>
```

SSE and download routes also accept `?token=<token>`. Requests and responses
are JSON unless the route explicitly handles PCAP data or multipart upload.
Validation errors use HTTP 400; a missing resource uses HTTP 404.

### Login

```http
POST /api/login
Content-Type: application/json

{"password":"...","display_name":"analyst"}
```

The response returns a Bearer token. `display_name` is used only for the
presence indicator in the dashboard.

## Routes

| Area | Method | Route | Purpose |
| --- | --- | --- | --- |
| Session | GET | `/api/session/active` | Online users (heartbeat-based) |
| Services | GET, POST | `/api/services` | List or create a service |
|  | GET, PUT, DELETE | `/api/services/{id}` | Read, update, or delete a service |
|  | POST | `/api/services/{id}/retry` | Immediately retry a listener bind |
|  | GET | `/api/proxy/statuses` | Listener status and latest bind error |
|  | POST | `/api/proxy/retry-all` | Retry every listener currently retrying |
| Traffic | GET | `/api/packets` | Query packets (`q`, `sort`, `limit`, `offset`) |
|  | GET, DELETE | `/api/packets/{id}` | Read or remove one packet |
|  | POST | `/api/packets/bulk-delete` | Remove a list of packet IDs |
|  | GET | `/api/packets/stream` | SSE packet and metadata stream |
|  | GET | `/api/packets/flow?packet_id=N` | Reconstruct a packet flow |
|  | GET | `/api/packets/flow/pcap?packet_id=N` | Download a flow as PCAP |
|  | GET | `/api/packets/exploit?packet_id=N` | Generate a Python exploit skeleton |
|  | GET | `/api/packets/decoded?packet_id=N` | Decode a protobuf/gRPC body |
|  | GET | `/api/packets/decoded-custom?packet_id=N[&protocol_id=P]` | Decode with a custom protocol |
| Rules | GET, POST | `/api/rules` | List or create rules |
|  | GET, PUT, DELETE | `/api/rules/{id}` | Read, update, or delete a rule |
|  | POST | `/api/rules/bulk-delete` | Remove rules by ID |
|  | GET | `/api/rules/presets` | List attack-preset categories |
|  | POST | `/api/rules/presets/apply` | Apply selected presets to services |
|  | POST | `/api/filter/validate` | Validate a filter expression |
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

`protocol` is one of `http`, `https`, `ws`, `wss`, `h2`, `grpc`, or `tcp`.
WebSocket services use `ws` for a cleartext listener and `wss` for a TLS
listener. TLS fields are
`tls_mode` (`selfsigned` or `challenge`), `cert_file`, `key_file`, and
`target_tls`. A gRPC service can set `proto_paths`; a TCP service can set
`protocol_id` to bind a custom decoder.

### Rules and packet search

The `pattern` field of a rule and the `q` parameter of packet/alert searches
share the same DSL. For example:

```text
method == "POST" AND url contains "/login" AND body matches "(?i)union"
```

See [FILTERS.md](FILTERS.md) for the complete language. Legacy packet search
parameters (`contains`, `regex`, `src_ip`, ...) remain available.

### PyFilters

Create or replace a script with:

```json
{
  "name": "block-admin-post",
  "code": "def match(flow):\n    return False\n",
  "enabled": true,
  "blocking": false
}
```

`POST /api/pyfilter-engine/test` accepts `name`, `code`, and one of `flow`,
`flows` (an ordered sequence), `packet_id`, or `flow_packet_id`. `repeat`
replays the same sequence to exercise module-level state. See
[PYFILTERS.md](PYFILTERS.md).

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
