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

### 1. Configure `.env`

```env
VM_IP=10.10.0.1
NETWORK_INTERFACE=eth0
TEAM_PASSWORD=changeme
FLAG_REGEX=[A-Z0-9]{31}=

# Auto-cleanup (0 = disabled)
CLEANUP_MAX_AGE_MINUTES=120
CLEANUP_MAX_DB_SIZE_MB=500

# Flag ID polling (set FLAGID_ENABLED=true to activate)
FLAGID_ENABLED=false
OUR_TEAM_ID=1
FLAGID_API_URL=http://10.10.0.1:8081/flagIds
FLAGID_POLL_INTERVAL=30

# Redis caching (improves performance on hot paths)
REDIS_PASSWORD=changeme_redis
```

### 2. Deploy

```bash
docker compose up -d
```

- **Frontend dashboard:** `http://<VM_IP>:3000`
- **Backend API:** `http://<VM_IP>:8080`
- **Redis:** `127.0.0.1:6379` (internal only, not exposed to the competition network)
- **Dozzle (container logs):** `http://localhost:9999` (internal only, bound to localhost)

For production (competition VM with host networking):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

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

The **Traffic** page shows all captured packets with real-time filters:

- Filter by service, source/destination IP, protocol
- Text search (`contains`) or regex search
- **Contains Flag** filter — shows packets matching the flag regex (yellow highlight)
- **Contains my Flag IDs** filter — shows packets containing your team's current flag ID values (teal highlight)
- Packets with both a flag and a flag ID display a combined yellow-to-teal gradient
- Flag regex matches are always highlighted in yellow in the detail panel; flag ID values in teal
- Click a packet to see full headers, body, and matched rules

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

From the **Drop Rules** page, create rules to block malicious requests:

- **String match** — exact substring in header/body/url
- **Regex match** — regex pattern
- **Byte sequence** — hex-encoded bytes for raw TCP

Each rule can have an action: **drop** (block), **alert** (log only), or **both**. The flag regex from `.env` is automatically loaded as an alert-only rule for all services — it highlights flag-bearing traffic without blocking it (blocking would break the checker).

### 8. Alerts

The **Alerts** page shows real-time alerts triggered by rules with `alert` or `both` action. Each alert shows the source IP, service, matched rule, and links to the full packet detail.

### 9. Configuration

The **Config** page lets you update:

- VM IP, network interface, team password, flag regex
- Auto-cleanup policies (max age, max DB size)
- Flag ID polling settings (API URL, team ID, poll interval) — when new flag IDs are fetched, old packets are retroactively scanned and marked
- A "Run cleanup now" button and current DB size display

### 10. Container logs (Dozzle)

The sidebar has a **Logs** link that opens [Dozzle](http://localhost:9999) in a new tab. Dozzle is a lightweight, read-only container log viewer that streams Docker container logs in real time. It shows all Janus containers (backend, frontend, redis, dozzle) and any other containers running on the host.

- Bound to `127.0.0.1:9999` only — not reachable from the competition network
- No authentication required (localhost access only — if an attacker has local access to the VM, they already have full control)

### 11. Redis caching

Redis is used as a performance cache for two hot paths:

- **Rules evaluation** — rules are cached per service, eliminating a JSON file read on every packet
- **Packet queries** — repeated identical queries are cached for 5 seconds

Redis is never the source of truth. If Redis is unreachable, Janus falls back to SQLite/JSON transparently with no loss of correctness.

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

All endpoints (except `/api/login`) require a `Bearer` token in the `Authorization` header.

| Method         | Endpoint                           | Description                                                                                                                                                                                 |
| -------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST           | `/api/login`                       | Authenticate with team password                                                                                                                                                             |
| GET            | `/api/services`                    | List services                                                                                                                                                                               |
| POST           | `/api/services`                    | Create service                                                                                                                                                                              |
| GET/PUT/DELETE | `/api/services/{id}`               | Get/update/delete service                                                                                                                                                                   |
| GET            | `/api/packets?...`                 | Query packets (filters: `service_id`, `service_name`, `src_ip`, `dst_ip`, `protocol`, `time_from`, `time_to`, `contains`, `regex`, `flagged`, `contains_flagid`, `sort`, `limit`, `offset`) |
| GET            | `/api/packets/flow?packet_id=X`    | Reconstruct full attack flow from a packet                                                                                                                                                  |
| GET            | `/api/packets/exploit?packet_id=X` | Generate Python exploit skeleton from flow                                                                                                                                                  |
| GET            | `/api/rules?service_id=...`        | List drop/alert rules                                                                                                                                                                       |
| POST           | `/api/rules`                       | Create rule                                                                                                                                                                                 |
| GET/PUT/DELETE | `/api/rules/{id}`                  | Get/update/delete rule                                                                                                                                                                      |
| GET            | `/api/alerts`                      | List alerts (filters: `service_id`, `rule_id`, `src_ip`, `time_from`, `time_to`)                                                                                                            |
| GET            | `/api/alerts/{id}`                 | Get alert detail                                                                                                                                                                            |
| DELETE         | `/api/alerts`                      | Clear all alerts                                                                                                                                                                            |
| GET/PUT        | `/api/config`                      | Read/update configuration                                                                                                                                                                   |
| GET/PUT        | `/api/config/cleanup`              | Read/update cleanup settings                                                                                                                                                                |
| POST           | `/api/cleanup/run`                 | Trigger immediate cleanup                                                                                                                                                                   |
| GET            | `/api/flagids`                     | Current flag ID map                                                                                                                                                                         |
| GET            | `/api/flagids/status`              | Flag ID poller status                                                                                                                                                                       |
| GET            | `/api/system/stats`                | VM resource metrics (CPU, RAM, disk, DB size, Redis)                                                                                                                                        |
