# Janus

Reverse proxy, packet sniffer, and traffic filtering system for CTF Attack & Defense competitions.

## How it works

In a CTF A/D competition, each team runs vulnerable services on a VM. Opponents and the checker connect to original service ports. Janus sits between them:

```
[Checker / Opponents] --> [Janus on original port] --> [Service on localhost:new_port]
```

1. Move your services to `localhost` (or different ports)
2. Configure Janus to listen on the original ports
3. Janus proxies traffic transparently, logs every packet, and can drop malicious requests

**Supported protocols:** HTTP/1.1, HTTPS/TLS, HTTP/2, gRPC, raw TCP (with optional custom binary decoders)

## Quick start

### 1. Create your `.env`

Copy the example and edit the few competition-specific values:

```bash
cp .env.example .env
```

Notable knobs (all documented in `.env.example`):

- `TEAM_IP` — your team address; services with an empty listen host bind to it, so you don't retype `10.60.x.y` for every service.
- `FLAG_REGEX_CASE_INSENSITIVE` / `FLAG_DECODE_URL` — catch flags that are case-mismatched or URL-encoded (e.g. `…%3D`).
- `PYFILTER_ENABLED` — the mitmproxy-style Python filter engine (see [Python filters](#python-filters-scriptable)).

### 2. Deploy

```bash
docker compose up -d
```

- **Frontend dashboard:** `http://localhost:2999` (localhost-only)
- **Backend API:** `http://localhost:8080` (localhost-only)
- **Redis:** `127.0.0.1:6379` (internal only)

### Competition VM (Linux)

On Linux competition VMs, Janus often needs to bind many “service ports” (original challenge ports). The easiest way is host networking for the `janus` container, while keeping the dashboard/API/Redis bound to localhost:

```bash
docker compose -f docker-compose.yml -f docker-compose-competition.yml up --build -d
```

### macOS development note

On macOS, Docker runs inside a VM (no true `--network host`). To test the reverse proxy from your host you must **publish the service ports** via Docker port mappings — that's why `docker-compose.yml` publishes a small port range.

### 3. Login

Open the dashboard and login with `TEAM_PASSWORD`. Each session picks a display name; the sidebar shows who else is currently online.

### 4. Add services

From the **Services** page, add each challenge service:

| Field          | Example          |
| -------------- | ---------------- |
| ID             | `web1`           |
| Name           | `Web Challenge`  |
| Listen Address | `10.10.0.1`      |
| Listen Port    | `8080`           |
| Target Address | `127.0.0.1:9080` |
| Protocol       | `http`           |

Optionally bind a **custom binary protocol** (defined in the Protocols page) or a `.proto` file (gRPC). Enable the service and Janus will start proxying immediately.

### 5. Monitor traffic

The **Traffic** page shows all captured packets with real-time updates via SSE (Server-Sent Events):

- **Live streaming** — new packets appear instantly; a **Pause/Resume** button freezes the view while you inspect
- **Unified filter expression** — single language for `body`, `header.X`, `url`, `method`, `status`, `round`, `src/dst/peer` (CIDR), `flagged`, `contains_flagid`, `dropped`, with `AND` / `OR` / `NOT`. See [FILTERS.md](FILTERS.md)
- **Contains Flag** filter highlights packets matching the flag regex (yellow)
- **Contains my Flag IDs** filter highlights packets carrying your team's current flag IDs (teal)
- Click a packet to see full headers, body, matched rules, and decoded payload (gRPC / custom protocol)
- Bulk-select packets to delete or export them as a PCAP

#### Live vs Static mode

Configurable from the **Config** page:

- **Live** (default): continuous capture, SSE streaming, periodic flag ID fetch + automatic backfill, auto-cleanup enabled.
- **Static**: manual capture **start/stop** (Traffic page button), manual "Apply Flag IDs" rescan, cleanup disabled — useful for offline analysis without losing evidence.

### 6. Copy Exploit

When you spot an interesting attack, turn it into a reusable exploit with one click:

1. Select any packet from a captured attack
2. Click **"Exploit"** in the detail panel (or **"Copy Exploit"** in the flow banner)
3. A ready-to-use Python script is copied to your clipboard

The generated exploit is compatible with [exploitfarm](https://github.com/pwnzer0tt1/exploitfarm) and includes `get_flagids(host)` and `exploit(host)` with the full reconstructed flow (`requests` for HTTP, `pwntools` for TCP).

**Flow reconstruction** correlates packets across multiple TCP connections via Bearer tokens, session cookies, or peer IP.

### 7. Drop & alert rules

From the **Rules** page, write rules using the same filter expression as Traffic:

```text
method == "POST" AND url contains "/login" AND body matches "(?i)(union|--|or 1=1)"
header.User-Agent matches "(?i)(sqlmap|nikto|nuclei)"
```

Each rule has an action: **drop** (block), **alert** (log only), or **both**. Flag and flag-ID detection is automatic — no per-service flag rules needed.

#### Attack Presets

**Presets** opens a library of ready-made rules for common CTF attack patterns. Pick categories and individual rules, choose target services, and create them in bulk. Categories: SQLi, XSS, Path Traversal, Command Injection, XXE, SSTI, PHP/Python/Node.js code exec, SSRF, Deserialization, Auth Bypass, NoSQLi, IDOR, Web Shells, File Upload, Flag Exfiltration.

#### Python filters (scriptable)

When the filter DSL can't express what you need — anything **stateful** or
cross-packet — use the **Python Filters** page (mitmproxy-style). Each script
defines a top-level `match(flow)` function that runs against every captured
packet; module-level state persists across calls, so you can count or correlate
over time. Matches surface on the **Alerts** page.

```python
# Alert when the same user logs in more than once.
import json
logins = {}

def match(flow):
    if flow["method"] == "POST" and flow["url"] == "/login":
        try:
            user = json.loads(flow["body"]).get("user")
        except Exception:
            user = None
        if user:
            logins[user] = logins.get(user, 0) + 1
            if logins[user] > 1:
                return f"repeated login for {user} (#{logins[user]})"
    return False
```

`match(flow)` returns `False`/`None` (no match), `True`, or a reason string.
`flow` exposes `method`, `url`, `status`, `headers` (dict), `body`, `src`,
`dst`, `service`, `direction`, `flagged`, `contains_flagid`, and more. Scripts
run in a bundled `python3` interpreter, off the proxy hot path; a hung or broken
script is isolated and never blocks traffic. Toggle the whole engine with
`PYFILTER_ENABLED` and point at a specific interpreter with `PYFILTER_PYTHON`.

You can **test** a script against an editable sample flow right on the page
before enabling it.

### 8. Custom protocols

The **Protocols** page lets you define **custom binary protocols** (length-prefixed strings, fixed-width ints, enums with dispatched payloads, computed-length blobs, etc.). Bind a protocol to a TCP service and Janus auto-decodes every packet body into a structured tree, viewable in the Traffic detail panel. For gRPC services, drop `.proto` files into the mounted `protos/` folder (or set `proto_paths` on the service) and Janus does the same with protobuf.

### 9. Alerts & Blocks

- **Alerts** — packets matched by rules with `alert` or `both` action. Filterable, sortable, links to the full packet.
- **Blocks** — packets actually dropped (`drop` / `both`). Same filter language; useful for auditing what your rules are killing.

### 10. Saved Flows

From the Traffic detail panel you can **pin** a flow (or an arbitrary selection of packets) to the **Saved Flows** page. Pinned flows snapshot the packets so they survive cleanup and can be reviewed/exported later.

### 11. Round Diff

The **Round Diff** page compares two scoreboard rounds for one or two services. The two rounds are asymmetric: round **A** is the *baseline* (reference) and round **B** is the round being *analyzed*. Janus pairs each packet in the analyzed round with its closest baseline twin and shows visual field diffs for URL, headers, status, and body — green is content added in B, red is content removed since A. It is content-based, not preset-based.

Pick rounds with the ◀/▶ steppers or the **Prev → current** button. The stats panel shows a Baseline → Analyzed comparison with per-metric deltas. Packet content changes are the primary view; **Route volume changes** (new / gone / Δ routes) and **Preset attack matches** are secondary, collapsible panels. Computation is cached for closed rounds and skips packets that are unchanged from the baseline, so even chatty services diff quickly.

Opening a packet flow from Round Diff preserves the view state, including selected services, rounds, loaded results, expanded diffs, collapsed panels, inspector packet, and scroll position, so you can return without losing your place.

### 12. PCAP import / export

- **Export** the current Traffic filter, a selection, or a single flow as a `.pcap`
- **Import** an existing `.pcap` and bind it to a (real or virtual) service to inspect it inside Janus
- Auto-save can dump every static-mode capture window to disk
- Files live under `PCAP_EXPORT_DIR` (default `data/pcap/`) and are listed/downloadable from the Traffic page

### 13. Filter Sandbox

The **Filter Sandbox** page lets you craft a filter expression against a sample packet and watch it evaluate live — handy for debugging complex rules before saving them.

### 14. System

The **System** page shows VM resource usage (CPU, RAM, disk, DB size, Redis). Auto-refreshed every few seconds.

### 15. Configuration

The **Config** page lets you update:

- Team password, flag regex, traffic mode (live/static), flow correlation window
- Auto-cleanup policies (max age, max DB size) — runs every minute
- Flag ID polling (format, API URL, team ID, poll interval, round duration, competition start, keep rounds) with a manual "Refresh Now" button
- PCAP export directory and auto-save toggle
- "Run cleanup now", "Clear Packets", "Purge Dropped" buttons and current DB size

### 16. Redis caching

Redis is used as a performance cache for the rules-evaluation hot path (cache invalidated on every rule create/update/delete). Redis is never the source of truth: if it's unreachable, Janus falls back to the persistent store transparently with no loss of correctness.

## Performance

Janus is designed to handle high-throughput CTF traffic (60+ teams, 8-hour matches). Key optimizations:

- **SQLite WAL mode** with separate read/write connection pools — readers never block writers
- **Aho-Corasick automaton** for O(text_length) multi-pattern flag ID matching
- **Optimized flag scanner** — known CTF flag patterns compiled into byte-level scanners that bypass `regexp` overhead
- **Smart backfill** — after each flag ID refresh, only re-scans packets from the last 60 seconds
- **Round-aware flag IDs** — keeps only the last N rounds in memory
- **SSE streaming** — new packets pushed with 100 ms batching, no polling
- **SQLITE_BUSY retry** — INSERTs retry with exponential backoff under contention

## Development (without Docker)

**Backend:**

```bash
cd backend
go run ./cmd/janus/
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` requests to `localhost:8080`.

## API

All endpoints (except `/api/login`) require a `Bearer` token in the `Authorization` header or a `?token=` query parameter (for SSE / file downloads).

The `q=` parameter on `/api/packets` and `/api/alerts` accepts the unified filter expression language documented in [FILTERS.md](FILTERS.md). Legacy per-field params (`contains`, `regex`, `src_ip`, …) are still supported.

### Auth & sessions

| Method | Endpoint              | Description                                           |
| ------ | --------------------- | ----------------------------------------------------- |
| POST   | `/api/login`          | Authenticate with team password, returns Bearer token |
| GET    | `/api/session/active` | List currently online users (heartbeat-based)         |

### Services

| Method         | Endpoint             | Description                  |
| -------------- | -------------------- | ---------------------------- |
| GET / POST     | `/api/services`      | List / create a service      |
| GET/PUT/DELETE | `/api/services/{id}` | Get / update / delete by ID  |

### Packets & flows

| Method     | Endpoint                           | Description                                                       |
| ---------- | ---------------------------------- | ----------------------------------------------------------------- |
| GET        | `/api/packets`                     | Query packets (`q=`, plus legacy filters, `sort`, `limit`, `offset`) |
| GET/DELETE | `/api/packets/{id}`                | Get or delete a single packet                                     |
| POST       | `/api/packets/bulk-delete`         | Delete a list of packet IDs                                       |
| GET        | `/api/packets/stream`              | SSE stream of new packets and metadata changes                    |
| GET        | `/api/packets/flow?packet_id=X`    | Reconstruct full attack flow from a packet                        |
| GET        | `/api/packets/flow/pcap?packet_id=X` | Download the flow as a `.pcap` file                             |
| GET        | `/api/packets/exploit?packet_id=X` | Generate Python exploit skeleton from the flow                    |
| GET        | `/api/packets/decoded?packet_id=X` | Decode a gRPC/protobuf body using `.proto` files                  |
| GET        | `/api/packets/decoded-custom?packet_id=X` | Decode a TCP body using the service's custom protocol      |

### Round diff

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| GET | `/api/round-diff?service_id=S&round_a=A&round_b=B` | Compare two rounds for a service and return content diffs for round B packets |

Query parameters:

| Name | Required | Description |
| ---- | -------- | ----------- |
| `service_id` | yes | Service ID to compare |
| `round_a` | yes | Baseline scoreboard round |
| `round_b` | yes | Round to inspect against the baseline |
| `top_k` | no | Max changed packets to return, `1..200` (default `24`) |
| `include_diff` | no | `1`/`true` includes inline field diffs; `0`/`false` returns summary metadata only |

The response includes `stats_a`, `stats_b`, `new_routes`, `gone_routes`, `changed_routes`, `suspicious_in_b`, and `novel_packets`. Each `novel_packets[]` entry includes packet metadata, `twin_packet_id`, `change_fields`, and, when `include_diff` is enabled, `field_diffs[]` entries for changed `url`, `headers`, `status`, and `body` fields. Closed-round results are cached; current/open rounds bypass the cache so late-arriving packets are not hidden.

### Rules & presets

| Method         | Endpoint                   | Description                                  |
| -------------- | -------------------------- | -------------------------------------------- |
| GET / POST     | `/api/rules`               | List / create drop & alert rules             |
| GET/PUT/DELETE | `/api/rules/{id}`          | Get / update / delete a rule                 |
| POST           | `/api/rules/bulk-delete`   | Delete a list of rule IDs                    |
| GET            | `/api/rules/presets`       | List attack preset categories                |
| POST           | `/api/rules/presets/apply` | Apply selected presets to services           |

### Python filters

| Method         | Endpoint                  | Description                                       |
| -------------- | ------------------------- | ------------------------------------------------- |
| GET / POST     | `/api/pyfilters`          | List (with engine status) / create a filter script |
| GET/PUT/DELETE | `/api/pyfilters/{id}`     | Get / update / delete a script                    |
| GET            | `/api/pyfilters/status`   | Engine health (python availability, worker, counts) |
| POST           | `/api/pyfilters/test`     | Evaluate a script against a sample flow or packet |

### Custom protocols

| Method         | Endpoint              | Description                                              |
| -------------- | --------------------- | -------------------------------------------------------- |
| GET / POST     | `/api/protocols`      | List / create a custom binary protocol definition        |
| GET/PUT/DELETE | `/api/protocols/{id}` | Get / update / delete a protocol                         |
| GET            | `/api/protos`         | List `.proto` files auto-discovered under `PROTO_DIR`    |
| POST           | `/api/protos/encode-field` | Encode a JSON field value back to protobuf bytes    |

### Alerts & blocks

| Method | Endpoint           | Description                                  |
| ------ | ------------------ | -------------------------------------------- |
| GET    | `/api/alerts`      | List alerts (same filter language as packets) |
| GET    | `/api/alerts/{id}` | Get alert detail                             |
| DELETE | `/api/alerts`      | Clear all alerts                             |

### Saved flows

| Method     | Endpoint                | Description                                                |
| ---------- | ----------------------- | ---------------------------------------------------------- |
| GET / POST | `/api/flows/saved`      | List / pin a flow (anchor packet or arbitrary selection)   |
| GET/DELETE | `/api/flows/saved/{id}` | Get full snapshot / delete a saved flow                    |

### Traffic capture (static mode)

| Method | Endpoint                           | Description                                            |
| ------ | ---------------------------------- | ------------------------------------------------------ |
| GET    | `/api/traffic/capture`             | Capture status (mode, capturing, current window)       |
| POST   | `/api/traffic/capture/start`       | Start a capture window (static mode)                   |
| POST   | `/api/traffic/capture/stop`        | Stop the current capture                               |
| POST   | `/api/traffic/capture/apply-flagids` | Re-scan captured packets with current flag IDs       |

### PCAP

| Method     | Endpoint                    | Description                                                |
| ---------- | --------------------------- | ---------------------------------------------------------- |
| POST       | `/api/pcap/export`          | Export packets matching a filter to a `.pcap` file         |
| POST       | `/api/pcap/export-selection`| Export an explicit list of packet IDs                      |
| GET        | `/api/pcap/files`           | List saved PCAP files                                      |
| GET/DELETE | `/api/pcap/files/{name}`    | Download / delete a PCAP file                              |
| POST       | `/api/pcap/import`          | Multipart upload of a `.pcap` (binds to a service)         |
| GET        | `/api/pcap/import/{id}`     | Progress of an ongoing import                              |

### Config & cleanup

| Method  | Endpoint                       | Description                                  |
| ------- | ------------------------------ | -------------------------------------------- |
| GET/PUT | `/api/config`                  | Read / update general configuration          |
| GET/PUT | `/api/config/cleanup`          | Read / update cleanup policies               |
| POST    | `/api/cleanup/run`             | Trigger immediate cleanup                    |
| POST    | `/api/cleanup/purge`           | Delete **all** packets and alerts            |
| POST    | `/api/cleanup/purge-packets`   | Delete all packets (keeps config)            |
| POST    | `/api/cleanup/purge-dropped`   | Delete only dropped/blocked packets          |

### Flag IDs

| Method | Endpoint                | Description                                                          |
| ------ | ----------------------- | -------------------------------------------------------------------- |
| GET    | `/api/flagids`          | Current flag ID map                                                  |
| GET    | `/api/flagids/status`   | Poller status (current round, keep rounds, last fetch)               |
| POST   | `/api/flagids/refresh`  | Trigger immediate flag ID fetch (auto-backfill follows)              |

### System & filter

| Method | Endpoint                | Description                                              |
| ------ | ----------------------- | -------------------------------------------------------- |
| GET    | `/api/system/stats`     | VM resource metrics (CPU, RAM, disk, DB size, Redis)     |
| POST   | `/api/filter/validate`  | Validate a filter expression — `{ ok, error?, position? }` |

> **Note:** Backfill is fully automatic — after every flag ID fetch, Janus re-scans packets from the last 60 seconds using the Aho-Corasick automaton. No manual backfill endpoint is exposed.

## Flag ID formats

Janus can parse multiple scoreboard flagId JSON formats. Select the format from the **Config → Flag IDs → Competition Format** dropdown (sent as `flagid_format` via `/api/config`).

### CyberChallenge (default)

The API shape is the “rounded” nested format used in CyberChallenge deployments (see `.env.example` for the variables).

```json
{
  "service1": {
    "1": {
      "5" : {
        "flag_id_description": "flag_id_service_service1_team_1_round_5"
      }
    },
    ...
  },
  ...
}
```

### saarCTF (`saarctf`)

```json
{
  "teams": [
    { "id": 1, "name": "NOP", "ip": "10.32.1.2" },
    { "id": 2, "name": "saarsec", "ip": "10.32.2.2" }
  ],
  "flag_ids": {
    "service_1": {
      "10.32.1.2": {
        "15": ["username1", "username1.2"],
        "16": ["username2", "username2.2"]
      },
      "10.32.2.2": {
        "15": ["username3", "username3.2"],
        "16": ["username4", "username4.2"]
      }
    },
    "service_2": {
      "10.32.1.2": {
        "15": "username3",
        "16": "username4"
      }
    }
  }
}
```

### FaustCTF (`faustctf`)

```json
{
  "teams": [123, 456, 789],
  "flag_ids": {
    "service1": {
      "123": ["abc123", "def456"],
      "789": ["xxx", "yyy"]
    }
  }
}
```
