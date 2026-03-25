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
```

### 2. Deploy

```bash
docker compose up -d
```

- **Frontend dashboard:** `http://<VM_IP>:3000`
- **Backend API:** `http://<VM_IP>:8080`

Both containers use host networking so Janus can bind to the competition VM IP directly.

### 3. Login

Open the dashboard and login with `TEAM_PASSWORD`.

### 4. Add services

From the **Services** page, add each challenge service:

| Field | Example |
|-------|---------|
| ID | `web1` |
| Name | `Web Challenge` |
| Listen Address | `10.10.0.1` |
| Listen Port | `8080` |
| Target Address | `127.0.0.1:9080` |
| Protocol | `http` |

Enable the service and Janus will start proxying immediately.

### 5. Monitor traffic

The **Traffic** page shows all captured packets with real-time filters:
- Filter by service, source/destination IP, protocol
- Text search (`contains`) or regex search
- Filter flagged packets (containing the flag pattern)
- Click a packet to see full headers, body, and matched rules

### 6. Drop rules

From the **Drop Rules** page, create rules to block malicious requests:
- **String match** — exact substring in header/body/url
- **Regex match** — regex pattern
- **Byte sequence** — hex-encoded bytes for raw TCP

The flag regex from `.env` is automatically loaded as a drop rule for all services (prevents flag exfiltration).

### 7. Configuration

The **Config** page lets you update VM IP, network interface, team password, and flag regex at runtime without editing `.env`.

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

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate with team password |
| GET | `/api/services` | List services |
| POST | `/api/services` | Create service |
| GET/PUT/DELETE | `/api/services/{id}` | Get/update/delete service |
| GET | `/api/packets?...` | Query packets (filters: `service_id`, `service_name`, `src_ip`, `dst_ip`, `protocol`, `time_from`, `time_to`, `contains`, `regex`, `flagged`, `sort`, `limit`, `offset`) |
| GET | `/api/rules?service_id=...` | List drop rules |
| POST | `/api/rules` | Create rule |
| GET/PUT/DELETE | `/api/rules/{id}` | Get/update/delete rule |
| GET/PUT | `/api/config` | Read/update configuration |
