# Janus

Janus is a reverse proxy, traffic recorder, and filtering console for
Attack/Defense CTFs. It sits on each challenge's original port, forwards the
connection to the relocated service, and lets the team inspect or block traffic
without changing the checker-facing endpoint.

```text
checker / opponents -> Janus (original service port) -> service (new local port)
```

It supports HTTP/1.1, HTTPS/TLS, WebSocket (WS/WSS), HTTP/2, gRPC, and raw TCP.
Traffic can be decoded with `.proto` files or custom binary protocol definitions.

## Documentation

Start here, then use the focused reference for the task at hand:

| Document | Use it for |
| --- | --- |
| [API.md](API.md) | REST endpoints, payloads, and authentication |
| [FLAGIDS.md](FLAGIDS.md) | Flag ID configuration and supported scoreboard formats |
| [FILTERS.md](FILTERS.md) | Filter-expression language used by Traffic and Rules |
| [PYFILTERS_QUICKSTART.md](PYFILTERS_QUICKSTART.md) | First small Python filters |
| [PYFILTERS.md](PYFILTERS.md) | Complete Python-filter API |
| [PYFILTERS_EXAMPLES.md](PYFILTERS_EXAMPLES.md) | Advanced, A/D-oriented Python-filter recipes |

## Quick start

### 1. Configure

```bash
cp .env.example .env
```

At minimum change `TEAM_PASSWORD`. Set `TEAM_IP` on the competition network so
services whose listen address has no host bind to the team address. Enable and
configure Flag IDs only when the scoreboard endpoint is available; see
[FLAGIDS.md](FLAGIDS.md).

Useful settings:

| Variable | Purpose |
| --- | --- |
| `TEAM_PASSWORD` | Dashboard login password |
| `TEAM_IP` | Default host for a service listener with no explicit host |
| `FLAG_REGEX` | Flag detector used for highlighting and filters |
| `FLAG_REGEX_CASE_INSENSITIVE` | Make flag matching ASCII case-insensitive |
| `FLAG_DECODE_URL` | Also scan a percent-decoded copy of traffic |
| `PYFILTER_ENABLED` | Enable the Python-filter engine (default `true`) |
| `TRAFFIC_MODE` | `live` (normal operation) or `static` (manual capture) |

### 2. Start Janus

For local development or macOS:

```bash
docker compose up --build -d
```

Open the dashboard at [http://localhost:2999](http://localhost:2999). The
frontend proxies `/api` to the backend; the normal Compose stack does not
publish the backend API as a separate host port. Service ports must be listed
in `docker-compose.yml` when Docker cannot use host networking.

For a Linux competition VM, host networking lets Janus bind arbitrary original
service ports:

```bash
docker compose -f docker-compose.yml -f docker-compose-competition.yml up --build -d
```

Review the exposure and bind settings in both Compose files before using this
on a competition network.

### 3. Add a service

In **Services**, add the checker-facing listener and its new backend address.

| Field | Example |
| --- | --- |
| Name | `Web challenge` |
| Listen address | `10.10.0.1` |
| Listen port | `8080` |
| Target address | `127.0.0.1:9080` |
| Protocol | `http` |

Janus generates the service ID when it is omitted. Enable the service to start
its listener immediately. The page also shows bind failures and can retry a
listener after the target service is rebuilt.

For a WebSocket service choose `ws`, or `wss` when clients connect to Janus
over TLS. `wss` uses the same TLS modes and certificate fields as `https`.
`Backend uses TLS` independently controls whether Janus connects to the target
using TLS, so both WS-to-WSS and WSS-to-WS deployments are supported.
After the upgrade, Janus unmasks client frames, reassembles fragmented messages,
and records text/binary messages up to 1 MiB in **Traffic** with method `WS`.
The negotiated `permessage-deflate` extension is removed so text payloads remain
inspectable; other WebSocket extensions are preserved.

## What Janus provides

- **Traffic** — live SSE updates, packet/flow inspection, unified filters,
  flag and Flag ID highlighting, PCAP import/export, and exploit skeletons.
- **Rules** — drop, alert, or both using the filter language. Attack presets
  can create a selected set of rules for multiple services.
- **PyFilters** — stateful Python scripts for detections that cannot be
  expressed in the DSL. Async scripts alert; blocking scripts can stop or
  rewrite the current request (and TCP response). Start with
  [PYFILTERS_QUICKSTART.md](PYFILTERS_QUICKSTART.md).
- **Protocols** — gRPC decoding from `.proto` files and editable custom binary
  decoders. Definitions support fixed, length-prefixed, computed-length, enum,
  and dispatched fields. A Python client snippet can be imported into a draft,
  then reviewed before saving.
- **Alerts and Blocks** — audit rule/PyFilter matches and traffic actually
  stopped by Janus.
- **Saved Flows** — persistent packet snapshots that survive normal cleanup,
  including inspection and copying of exact packet bytes.
- **Round Diff** — baseline-vs-analyzed round comparison of packet content,
  routes, and suspicious changes.
- **System and Config** — resource usage, capture mode, cleanup, flag matching,
  Flag IDs, PCAP settings, and flow-correlation configuration.

## Traffic modes

| Mode | Behaviour |
| --- | --- |
| `live` | Captures continuously, streams events, polls Flag IDs, automatically backfills recent traffic after a changed Flag ID response, and runs cleanup. |
| `static` | Capture is started/stopped manually. Polling, automatic backfill, and cleanup are disabled; use **Apply Flag IDs** to rescan the captured window. |

## Common workflows

### Inspect and turn traffic into an exploit

1. Find a request in **Traffic** using the filter language.
2. Inspect the packet or reconstructed flow.
3. Use **Exploit** / **Copy Exploit** to create a Python skeleton compatible
   with exploitfarm. Flow reconstruction correlates bearer tokens, cookies, and
   then peer information inside the configured time window.

### Block an attack without breaking the checker

1. Reproduce the request in **Filter Sandbox** or locate it in Traffic.
2. Add an alert rule first, verify its scope, then change its action to drop.
3. For state or protocol-aware logic, write a PyFilter and run it against a
   saved packet or a whole reconstructed flow before enabling it.

### Decode a non-HTTP service

1. Bind a `.proto` file to a gRPC service, or create a custom protocol in
   **Protocols**.
2. For a Python challenge client, use **Import Python** to obtain a draft.
3. Review field lengths, computed lengths, enums, dispatches, and warnings;
   save the decoder and bind it to the TCP service.

## Performance and storage

Janus uses SQLite WAL with separate read/write pools, Redis as a rule-evaluation
cache, Aho-Corasick matching for Flag IDs, optimized flag scanning, and batched
SSE delivery. Redis is a cache only: traffic and configuration remain correct if
it is unavailable.

Runtime data, saved PyFilters, SQLite data, and exported PCAPs live beneath
`DATA_DIR` (mounted as `./data` by Compose). Treat this directory as operational
state and back it up if you need evidence after the match.

## Development without Docker

```bash
cd backend
go run ./cmd/janus/
```

```bash
cd frontend
npm install
npm run dev
```

The Vite development proxy targets `http://localhost:9090` in the current
Compose-oriented setup. When running the backend directly, its address is
controlled by `API_BIND` and `API_PORT`.
