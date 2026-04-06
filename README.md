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

**Supported protocols:** HTTP/1.1, HTTPS/TLS, HTTP/2, gRPC, raw TCP

## Quick start

### 1. Create your `.env`

Copy the example and edit the few competition-specific values:

```bash
cp .env.example .env
```

### 2. Deploy

```bash
docker compose up -d
```

- **Frontend dashboard:** `http://localhost:2999` (localhost-only)
- **Backend API:** `http://localhost:8080` (localhost-only)
- **Redis:** `127.0.0.1:6379` (internal only, not exposed to the competition network)
- **Dozzle (container logs):** `http://localhost:9999` (internal only, bound to localhost)

### Competition VM (Linux)

On Linux competition VMs, Janus often needs to bind many “service ports” (original challenge ports). The easiest way is host networking for the `janus` container, while keeping the dashboard/API/Redis bound to localhost:

```bash
docker compose -f docker-compose.yml -f docker-compose-competition.yml up --build -d
```

### macOS development note (why ports are published)

On macOS, Docker runs inside a VM (no true `--network host`). If you want to test the reverse proxy from your host (or another machine) you must **publish the service ports you want Janus to listen on** via Docker port mappings. That’s why `docker-compose.yml` publishes a small port range for proxied services.

### 3. Login

Open the dashboard and login with `TEAM_PASSWORD`.

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

Enable the service and Janus will start proxying immediately.

### 5. Monitor traffic

The **Traffic** page shows all captured packets with real-time updates via SSE (Server-Sent Events):

- **Live streaming** — new packets appear instantly without polling; a **Pause/Resume** button lets you freeze the view while inspecting traffic
- Filter by service, source/destination IP, protocol
- Text search (`contains`) or regex search
- **Contains Flag** filter — shows packets matching the flag regex (yellow highlight)
- **Contains my Flag IDs** filter — shows packets containing your team's current flag ID values (teal highlight)
- Packets with both a flag and a flag ID display a combined yellow-to-teal gradient
- Flag regex matches are always highlighted in yellow in the detail panel; flag ID values in teal
- Click a packet to see full headers, body, and matched rules

#### Live vs Static mode

Janus supports two traffic modes (configurable from the **Config** page):

- **Live** (default): continuous capture, SSE streaming enabled, periodic flagId fetch + automatic smart backfill, auto-cleanup policies enabled.
- **Static**: manual capture start/stop (useful for offline analysis or when you want to “freeze” ingestion), periodic flagId fetch/backfill is disabled, and auto-cleanup policies are disabled to avoid deleting evidence while reviewing.

### 6. Copy Exploit

When you spot an interesting attack in the Traffic page, you can turn it into a reusable exploit with one click:

1. Select any packet from a captured attack
2. Click **"Exploit"** in the detail panel (or **"Copy Exploit"** in the flow banner)
3. A ready-to-use Python script is copied to your clipboard

The generated exploit is compatible with [exploitfarm](https://github.com/pwnzer0tt1/exploitfarm) and includes:

- `get_flagids(host)` to fetch flag IDs from the CyberChallenge scoreboard
- `exploit(host)` with the full reconstructed attack flow
- `requests` + `session()` for HTTP services, `pwntools` for TCP services

**Flow reconstruction** automatically tries to correlate packets across multiple TCP connections using Bearer tokens, session cookies (`Cookie`/`Set-Cookie`), or peer IP when no session identifiers exist.

### 7. Drop rules

From the **Rules** page, create rules to block malicious requests:

- **String match** — exact substring in header/body/url
- **Regex match** — regex pattern
- **Byte sequence** — hex-encoded bytes for raw TCP

Each rule can have an action: **drop** (block), **alert** (log only), or **both**.

Flag and flag ID detection is handled automatically at the packet level (via the flag scanner and Aho-Corasick matcher) — no per-service flag rules are needed.

#### Attack Presets

Click **Presets** to open a library of ready-made rules for common CTF attack patterns. Select categories and individual rules, choose which services to apply them to, and create them in bulk. Available categories:

| Category              | Examples                                                              |
| --------------------- | --------------------------------------------------------------------- |
| SQL Injection         | UNION SELECT, blind SLEEP/BENCHMARK, stacked queries, SQLite-specific |
| XSS                   | script tags, event handlers, javascript: URI                          |
| Path Traversal        | dot-dot-slash, /etc/passwd, /proc/self, null byte                     |
| Command Injection     | shell metacharacters, reverse shells, IFS bypass                      |
| XXE                   | DOCTYPE, ENTITY, SYSTEM file/http                                     |
| SSTI                  | Jinja2 `{{ }}` / `{% %}`, `${...}`, dunder chains                     |
| PHP                   | code execution, eval/assert, wrappers, deserialization                |
| Python                | os/subprocess, eval/exec, pickle, dunder chains                       |
| Node.js               | child_process, eval/Function, prototype pollution                     |
| Flag Exfiltration     | curl/wget outbound, nc/ncat, DNS exfil, base64 pipe                   |
| SSRF                  | internal IPs, localhost, metadata endpoints, file/gopher/dict schemes |
| Deserialization       | Java serialized objects, gadget chains, Python pickle, .NET           |
| Auth Bypass           | JWT none/confusion, admin params, mass assignment                     |
| NoSQL Injection       | $gt/$ne operators, $where JS, $or bypass                              |
| IDOR / Access Control | sequential ID scan, admin paths, method override                      |
| Web Shell / Backdoor  | known shells, cmd params, suspicious User-Agents                      |
| File Upload           | PHP extensions, double extensions, null byte, SVG XSS                 |

### 8. Alerts

The **Alerts** page shows real-time alerts triggered by rules with `alert` or `both` action. Each alert shows the source IP, service, matched rule, and links to the full packet detail.

### 9. Configuration

The **Config** page lets you update:

- Team password, flag regex, traffic mode, flow correlation window
- Auto-cleanup policies (max age, max DB size) — cleanup runs every 1 minute
- Flag ID polling settings (format, API URL, team ID, poll interval, round duration, competition start, keep rounds) — with a manual "Refresh Now" button (backfill runs automatically after each fetch)
- Competition timing: round duration, competition start time, number of rounds to keep
- A "Run cleanup now" button, "Clear Packets" button (deletes all packets but keeps config), and current DB size display

### 10. Container logs (Dozzle)

The sidebar has a **Logs** link that opens [Dozzle](http://localhost:9999) in a new tab. Dozzle is a lightweight, read-only container log viewer that streams Docker container logs in real time. It shows all Janus containers (backend, frontend, redis, dozzle) and any other containers running on the host.

- Bound to `127.0.0.1:9999` only — not reachable from the competition network
- No authentication required (localhost access only — if an attacker has local access to the VM, they already have full control)

### 11. Redis caching

Redis is used as a performance cache for the rules evaluation hot path:

- **Rules evaluation** — rules are cached per service; the cache is invalidated automatically whenever a rule is created, updated, or deleted

Redis is never the source of truth. If Redis is unreachable, Janus falls back to the persistent store transparently with no loss of correctness.

## Performance

Janus is designed to handle high-throughput CTF traffic (60+ teams, 8-hour matches). Key optimizations in this version:

- **SQLite WAL mode** with separate read/write connection pools — readers never block writers, writers never block readers
- **Aho-Corasick automaton** (via `petar-dambovaliev/aho-corasick`) for O(text_length) multi-pattern flag ID matching instead of per-value `strings.Contains` loops
- **Optimized flag scanner** — parses known CTF flag regex patterns (e.g. `[A-Z0-9]{31}=`, `FLAG{.*}`) into byte-level scanners that avoid regexp overhead on the hot path
- **Smart backfill** — after each flag ID refresh, only re-scans packets from the last 60 seconds (the "limbo" window between round start and fetch completion), not the entire DB
- **Round-aware flag IDs** — keeps only the last N rounds of flag IDs in memory; old rounds are pruned automatically
- **SSE streaming** — new packets are pushed to the frontend via Server-Sent Events with 100ms batching, eliminating the 1-second polling overhead
- **SQLITE_BUSY retry** — INSERT operations retry with exponential backoff to handle contention between proxy traffic and backfill writes

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

All endpoints (except `/api/login`) require a `Bearer` token in the `Authorization` header or a `?token=` query parameter (for EventSource/SSE).

| Method         | Endpoint                           | Description                                                                                                                                                                                 |
| -------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST           | `/api/login`                       | Authenticate with team password                                                                                                                                                             |
| GET            | `/api/services`                    | List services                                                                                                                                                                               |
| POST           | `/api/services`                    | Create service                                                                                                                                                                              |
| GET/PUT/DELETE | `/api/services/{id}`               | Get/update/delete service                                                                                                                                                                   |
| GET            | `/api/packets?...`                 | Query packets (filters: `service_id`, `service_name`, `src_ip`, `dst_ip`, `protocol`, `time_from`, `time_to`, `contains`, `regex`, `flagged`, `contains_flagid`, `sort`, `limit`, `offset`) |
| GET            | `/api/packets/stream`              | SSE stream of new packets and metadata-change notifications                                                                                                                                 |
| GET            | `/api/packets/flow?packet_id=X`    | Reconstruct full attack flow from a packet                                                                                                                                                  |
| GET            | `/api/packets/exploit?packet_id=X` | Generate Python exploit skeleton from flow                                                                                                                                                  |
| GET            | `/api/rules?service_id=...`        | List drop/alert rules                                                                                                                                                                       |
| POST           | `/api/rules`                       | Create rule                                                                                                                                                                                 |
| GET/PUT/DELETE | `/api/rules/{id}`                  | Get/update/delete rule                                                                                                                                                                      |
| GET            | `/api/rules/presets`               | List available attack preset categories                                                                                                                                                     |
| POST           | `/api/rules/presets/apply`         | Apply selected presets to services (`{ service_ids, selected }`)                                                                                                                            |
| GET            | `/api/alerts`                      | List alerts (filters: `service_id`, `rule_id`, `src_ip`, `time_from`, `time_to`)                                                                                                            |
| GET            | `/api/alerts/{id}`                 | Get alert detail                                                                                                                                                                            |
| DELETE         | `/api/alerts`                      | Clear all alerts                                                                                                                                                                            |
| GET/PUT        | `/api/config`                      | Read/update configuration                                                                                                                                                                   |
| GET/PUT        | `/api/config/cleanup`              | Read/update cleanup settings                                                                                                                                                                |
| POST           | `/api/cleanup/run`                 | Trigger immediate cleanup                                                                                                                                                                   |
| POST           | `/api/cleanup/purge`               | Delete all packets and alerts                                                                                                                                                               |
| POST           | `/api/cleanup/purge-packets`       | Delete all packets (keeps config)                                                                                                                                                           |
| GET            | `/api/flagids`                     | Current flag ID map                                                                                                                                                                         |
| GET            | `/api/flagids/status`              | Flag ID poller status (includes current round, keep rounds)                                                                                                                                 |
| POST           | `/api/flagids/refresh`             | Trigger immediate flag ID fetch (backfill runs automatically)                                                                                                                               |
| GET            | `/api/system/stats`                | VM resource metrics (CPU, RAM, disk, DB size, Redis)                                                                                                                                        |

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
