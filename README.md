# Janus

Janus is a reverse proxy, traffic recorder, and filtering console for
Attack/Defense CTFs. It sits on each challenge's original port, forwards the
connection to the relocated service, and lets the team inspect or block traffic
without changing the checker-facing endpoint.

```text
checker / opponents -> Janus (original service port) -> service (new local port)
```

It supports HTTP/1.1, HTTPS/TLS, WebSocket (WS/WSS), HTTP/2 (TLS or h2c),
gRPC, raw/line/TLS TCP, UDP, DNS, Redis RESP2, and MQTT. Traffic can be
decoded with built-in decoders, `.proto` files, or custom binary definitions.

## Documentation

Start here, then use the focused reference for the task at hand:

| Document | Use it for |
| --- | --- |
| [DEPLOYMENT.md](DEPLOYMENT.md) | CI releases, amd64/arm64 artifacts, and split frontend/backend deployment over a VPN |
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
| `PYFILTER_ENABLED` | Initial Python-filter processing state; also switchable live from Config (default `true`) |
| `SCORING_ENABLED` | Initial deterministic scoring state; also switchable live from Config (default `true`) |
| `BASELINE_START_ROUND` / `BASELINE_END_ROUND` | Default inclusive rounds used by the deterministic checker baseline (`1`–`5`); Config can override them per service |
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

Redis is optional. The default single-process setup uses SQLite plus in-memory
compiled rule bundles. To enable the cache adapter, set `REDIS_ADDR=redis:6379`
and start Compose with `--profile cache`. Otherwise leave `REDIS_ADDR` empty:
the Redis container stays off and this is the recommended competition setup.

For a Linux competition VM, host networking lets Janus bind arbitrary original
service ports:

```bash
docker compose -f docker-compose.yml -f docker-compose-competition.yml up --build -d
```

Review the exposure and bind settings in both Compose files before using this
on a competition network. `docker compose ps` should report both `janus` and
`frontend` as healthy before challenge ports are moved.

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

The protocol selector is a preset: Janus automatically derives transport,
application profile, client-side TLS, upstream TLS and framing into the
versioned service model. Existing `services.json` records are migrated on first
load. No manual conversion is required; advanced certificate/decoder settings
remain available under **Advanced settings**.

To migrate a challenge Compose file, run the included interactive helper first
with `--dry-run`, then without it after reviewing every service:

```bash
./scripts/janus_compose_ports.py --dry-run /path/to/challenge
./scripts/janus_compose_ports.py /path/to/challenge
```

It supports the same TCP/UDP protocol presets as the UI, preserves `/udp`
Compose mappings and switches the challenge ports only after Janus service,
certificate and `.proto` files have been written atomically. Unknown encrypted
protocols default to raw TCP passthrough; choose TLS termination only when the
original certificate behaviour is known.

The standard bridge Compose profile binds listeners inside the container on
the wildcard address while preserving the configured checker-facing IP. The
competition host-network profile binds the configured IP directly. This is
selected by the Compose profiles; the service form needs no extra option.

For a WebSocket service choose `ws`, or `wss` when clients connect to Janus
over TLS. `wss` uses the same TLS modes and certificate fields as `https`.
`Backend uses TLS` independently controls whether Janus connects to the target
using TLS, so both WS-to-WSS and WSS-to-WS deployments are supported.
After the upgrade, Janus unmasks client frames, reassembles fragmented messages,
and exposes text/binary messages in clear form in **Traffic** with method `WS`.
Rules can drop a client message before it reaches the backend; blocking
PyFilters can drop or rewrite messages in either direction without closing the
WebSocket session. Subprotocol negotiation is preserved, while WebSocket
extensions are disabled because they can transform the application payload and
bypass generic filtering. Messages larger than 1 MiB are dropped and audited.

## What Janus provides

- **Traffic** — live SSE updates, packet/flow inspection, simple search plus
  filter DSL, deterministic exploit/checker confidence, flag and Flag ID
  highlighting, PCAP import/export, and exploit skeletons.
- **Rules** — drop, alert, or both using the filter language. Attack presets
  can create a selected set of alert rules for multiple services. New rules
  start as alerts and require an explicit operator choice before they block.
- **PyFilters** — stateful Python scripts for detections that cannot be
  expressed in the DSL. Observe scripts alert; inline scripts can stop,
  close, or rewrite HTTP/HTTPS, TCP, UDP, and WebSocket traffic within the
  protocol limits described in the [reference](PYFILTERS.md). Start with
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

For a conservative initial rule set, validate and seed only the categories
needed by each service:

```bash
./scripts/seed_rules.py --password "$TEAM_PASSWORD" --validate-only
./scripts/seed_rules.py --password "$TEAM_PASSWORD" --service web --category sqli --category path
```

The curated seed is idempotent and alert-only. Observe real checker traffic
before manually promoting a narrow service-specific rule to `drop` or `both`;
do not seed every category blindly on every service.

### Choose a safe opening baseline

Janus estimates exploit/checker confidence with deterministic signatures and
rules only—there is no AI or learned model. In **Config**, choose a default
inclusive opening range and optional service-specific ranges. A signature becomes trusted checker traffic
only after it appears in every selected round; a distinct exploit fingerprint
seen in one round therefore remains untrusted. Truncated flows, request flags,
rule/suspicion matches, and flows labelled `exploit` are excluded.

Scoring inspects request URL/body and application-controlled headers, while
ignoring HTTP negotiation/transport headers such as `Accept-Encoding`.
Generic syntax and baseline novelty are weak evidence; `likely_exploit`
requires corroboration such as a rule decision, a flag, or a suspicious server
outcome. In **Traffic**, **Hide score** removes the summary, quick filters,
table column and detail card; the preference is kept in the browser and can be
restored with **Show Janus score**.

No static method can separate an exploit that is structurally identical to a
recurring checker flow, or prove that a safe-looking exploit repeated unchanged
in every selected round is legitimate. If the opening window was contaminated,
label the captured flow as `exploit`, adjust the range if needed, then use
**Rebuild from captured traffic**. Baselines are versioned by timing and round
selection, independently from captured packets: autoclean cannot remove them,
and reselecting an old range restores its fingerprint snapshot even when its
raw traffic is gone. A manual rebuild replaces the active snapshot only after
retained safe traffic covers all required rounds; otherwise Janus keeps the
previous snapshot unchanged.

### Decode a non-HTTP service

1. Select DNS, RESP, or MQTT directly in **Services** for built-in decoding;
   bind a `.proto` to gRPC, or create a custom definition in **Protocols**.
2. For a Python challenge client, use **Import Python** to obtain a draft.
3. Review field lengths, computed lengths, enums, dispatches, and warnings;
   save the decoder and bind it to the TCP service.

## Performance and storage

Janus uses SQLite WAL with separate read/write pools, per-service compiled rule
bundles, Aho-Corasick matching for Flag IDs, optimized flag scanning, and
batched SSE delivery. Redis is an optional cache adapter: traffic and
configuration remain correct when it is disabled or unavailable.

Automatic cleanup runs in short time-budgeted batches and uses SQLite's logical used space
rather than allocated database/WAL file size. Freed pages are reused and WAL
pages are passively checkpointed, avoiding long automatic `VACUUM` pauses.
Traffic clients receive one refresh after cleanup and targeted SSE patches when
deterministic flow scores change.

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
