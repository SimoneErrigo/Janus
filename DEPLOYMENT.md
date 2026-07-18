# Releases and split deployment over a VPN

This guide covers the fastest competition setup for Janus:

- run the backend directly on the vulnbox with `./janus`;
- run the frontend on a second machine;
- connect frontend and backend through a private VPN.

No Go or Node.js runtime is required when using release artifacts. The native
backend is a single static Linux binary, while the frontend is a static bundle
served by nginx.

The browser only talks to the frontend. Nginx forwards `/api` to the backend
through the VPN, keeping the dashboard and API on the same origin. This is
important for sessions, SSE updates, and downloads.

## What GitHub Actions builds

The [`ci.yml`](.github/workflows/ci.yml) workflow runs on pushes to `main`, pull
requests, and manual dispatch. It performs:

- Go tests, `go vet`, and module verification;
- backend cross-builds for `linux/amd64` and `linux/arm64`;
- frontend linting and production builds with Node.js 22.

The [`release.yml`](.github/workflows/release.yml) workflow runs when a tag
matching `vX.Y.Z` is pushed:

```bash
git tag -a v0.1.0 -m "Janus v0.1.0"
git push origin v0.1.0
```

It creates a GitHub Release containing:

```text
janus-backend-v0.1.0-linux-amd64.tar.gz
janus-backend-v0.1.0-linux-arm64.tar.gz
janus-frontend-v0.1.0.tar.gz
SHA256SUMS
```

It also publishes multi-architecture container images:

```text
ghcr.io/simoneerrigo/janus-backend:0.1.0
ghcr.io/simoneerrigo/janus-frontend:0.1.0
```

Both images support `linux/amd64` and `linux/arm64`. The Vite frontend bundle is
plain HTML, CSS, and JavaScript, so a single frontend archive works on either
architecture.

## Quick deployment

### 1. Download the release

Download the backend archive for the vulnbox architecture and `SHA256SUMS`
from the same GitHub Release. Detect the correct architecture with:

```bash
VERSION=v0.1.0
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture"; exit 1 ;;
esac
```

Verify the downloaded files before extracting them:

```bash
sha256sum -c SHA256SUMS
tar -xzf "janus-backend-${VERSION}-linux-${ARCH}.tar.gz"
cd "janus-backend-${VERSION}-linux-${ARCH}"
```

Frontend and backend should always come from the same release version.

### 2. Create the backend `.env`

The release already includes `.env.example`. Copy it, create the local data
directories, and edit the configuration:

```bash
cp .env.example .env
mkdir -p data data/pcap protos certs
${EDITOR:-vi} .env
```

The following is a useful starting profile:

```dotenv
TEAM_PASSWORD=REPLACE_WITH_A_LONG_URL_SAFE_SECRET

# Competition address for proxied services.
TEAM_IP=10.60.25.1
DATA_BIND_MODE=configured

# Private VPN address used by the remote frontend.
API_BIND=10.200.0.2
API_PORT=9090

# Relative paths are resolved from this extracted release directory.
DATA_DIR=./data
PROTO_DIR=./protos
PCAP_EXPORT_DIR=./data/pcap
PCAP_AUTO_SAVE=false

TRAFFIC_MODE=live
FLOW_CORRELATION_WINDOW_SECONDS=120
CLEANUP_MAX_AGE_MINUTES=20
CLEANUP_MAX_DB_SIZE_MB=250

FLAG_REGEX=[A-Z0-9]{31}=
FLAG_REGEX_CASE_INSENSITIVE=false
FLAG_DECODE_URL=true

FLAGID_ENABLED=false
FLAGID_API_URL=
OUR_TEAM_ID=
FLAGID_FORMAT=cyberchallenge
FLAGID_POLL_INTERVAL=30

ROUND_DURATION=120
COMPETITION_START=
KEEP_ROUNDS=5
BASELINE_START_ROUND=1
BASELINE_END_ROUND=5
SCORING_ENABLED=true

REDIS_ADDR=
REDIS_PASSWORD=

# Keep this disabled unless trusted Python filters are actually required.
PYFILTER_ENABLED=false
PYFILTER_PYTHON=
```

Replace:

- `10.60.25.1` with the vulnbox address on the competition network;
- `10.200.0.2` with the vulnbox address on the VPN;
- the password with a long random secret that is never committed.

The `.env` parser splits each line at the first `=`, but it does not interpret
shell quotes or expand variables. For example, `TEAM_PASSWORD="secret"`
includes the quote characters in the password. Use unquoted values. An `=`
inside a value is valid.

### 3. Start Janus directly

From the extracted backend directory, run:

```bash
./janus
```

That is enough: Janus automatically reads `.env` from its current working
directory. Open the frontend, configure the services, and leave this terminal
running. Stop Janus with `Ctrl-C`.

If you want to reduce Janus's RAM usage, launch it with optional Go runtime
limits instead:

```bash
GOMEMLIMIT=850MiB GOGC=50 ./janus
```

`GOMEMLIMIT` and `GOGC` trade some additional garbage-collection work for a
lower memory footprint. They are process variables read by the Go runtime, so
keep them in the launch command rather than `.env`. Adjust or omit them when
memory usage is not a concern.

After changing a startup setting in `.env`, stop Janus and run the same command
again. The file is not embedded in the binary and startup settings are not
hot-reloaded.

Python 3 is only required when Python-filter processing is enabled. The initial
state comes from `PYFILTER_ENABLED`, and both Python filters and scoring can be
paused or resumed immediately from **Config** without changing live capture.

### Leaving Janus running

For a quick match-day setup, `tmux` is the simplest option:

```bash
tmux new -s janus
./janus
```

Detach with `Ctrl-B`, then `D`. Reattach later with:

```bash
tmux attach -t janus
```

If `tmux` is not available, use `nohup`:

```bash
nohup ./janus >janus.log 2>&1 &
echo $! > janus.pid
tail -f janus.log
```

Stop the background process gracefully with:

```bash
kill "$(cat janus.pid)"
```

Avoid `kill -9`: HTTP shutdown may take up to 15 seconds, and Janus allows up
to two minutes for PCAP imports already in progress to finish.

### Move vulnerable services behind Janus

For each challenge:

1. Create a disabled Janus service that listens on the original port and on
   `TEAM_IP`, targeting `127.0.0.1:new_port`.
2. Move the vulnerable service to the new port, preferably bound only to
   loopback.
3. Enable the Janus listener immediately and verify that its status is
   **running**.

Example:

```text
Listen address: 10.60.25.1
Listen port:    80
Target address: 127.0.0.1:10080
Protocol:       http
```

`DATA_BIND_MODE=configured` is correct for the native binary and host-network
containers. The `wildcard` mode is intended for Docker bridge networking.

Changing `TEAM_IP` does not rewrite listener addresses already saved in Janus.
Update those services from the Services page after a network change.

## Start the frontend on the remote machine

### Recommended: frontend container

The container automatically selects amd64 or arm64. Set `API_BACKEND` to the
backend's VPN address, not its competition-network address:

```bash
docker pull ghcr.io/simoneerrigo/janus-frontend:0.1.0
docker run -d --name janus-frontend --restart unless-stopped -p 10.200.0.3:2999:3000 -e API_BACKEND=10.200.0.2 -e API_BACKEND_PORT=9090 -e FRONTEND_BIND=0.0.0.0 -e FRONTEND_PORT=3000 ghcr.io/simoneerrigo/janus-frontend:0.1.0
```

In this example:

- `10.200.0.3` is an address on the frontend machine that teammates can reach;
- `10.200.0.2` is the vulnbox VPN address;
- users open `http://10.200.0.3:2999`.

The published frontend address may instead be a management or private team
address. The browser never contacts the vulnbox directly: it requests `/api`
from the dashboard origin, and nginx proxies it through the VPN.

To change a container's environment variables, remove and recreate the
container. `docker restart` keeps the old environment.

Useful commands:

```bash
docker logs -f janus-frontend
docker stop janus-frontend
docker start janus-frontend
```

### Alternative: static archive and an existing nginx

The frontend archive contains `dist/` and `nginx.conf.template`. If nginx and
`envsubst` are already installed, extract the archive and run:

```bash
VERSION=v0.1.0
tar -xzf "janus-frontend-${VERSION}.tar.gz"
cd "janus-frontend-${VERSION}"

sudo install -d -o root -g root -m 0755 /var/www/janus
sudo cp -R dist/. /var/www/janus/

export API_BACKEND=10.200.0.2
export API_BACKEND_PORT=9090
export FRONTEND_BIND=10.200.0.3
export FRONTEND_PORT=2999
export FRONTEND_ROOT=/var/www/janus

envsubst '${API_BACKEND} ${API_BACKEND_PORT} ${FRONTEND_BIND} ${FRONTEND_PORT} ${FRONTEND_ROOT}' < nginx.conf.template | sudo tee /etc/nginx/conf.d/janus.conf >/dev/null
sudo nginx -t
sudo nginx -s reload
```

Restrict `envsubst` to exactly those five variables. An unrestricted
substitution would remove native nginx variables such as `$http_host`,
`$remote_addr`, `$scheme`, and `$uri`.

The template provides same-origin `/api` proxying, unbuffered SSE, React route
fallback, and a 257 MiB PCAP upload limit. The dedicated document root avoids
overwriting other nginx sites.

The template serves HTTP. If the dashboard is exposed outside a trusted team
network, terminate TLS in nginx or in a trusted reverse proxy in front of it.

### Why the frontend has no `.env`

After `npm run build`, the frontend is only a set of static files. The
`API_BACKEND`, `API_BACKEND_PORT`, `FRONTEND_BIND`, `FRONTEND_PORT`, and
`FRONTEND_ROOT` variables configure nginx when it starts; they are not compiled
into the React bundle. They can therefore be changed without rebuilding the
frontend.

## Optional: run the backend container instead

The native `./janus` launch has less overhead. If Docker is already part of the
competition setup, the multi-architecture backend image is also available:

```bash
docker pull ghcr.io/simoneerrigo/janus-backend:0.1.0
docker run -d --name janus-backend --restart unless-stopped --network host --env-file "$(pwd)/.env" -e ENV_PATH=/dev/null -e DATA_DIR=/data -e PROTO_DIR=/protos -e PCAP_EXPORT_DIR=/data/pcap -v "$(pwd)/data:/data" -v "$(pwd)/protos:/protos:ro" -v "$(pwd)/certs:/certs:ro" ghcr.io/simoneerrigo/janus-backend:0.1.0
```

Run this from the backend release directory after creating `.env` and the data
directories. The explicit container paths override the relative paths in the
host `.env`. The image includes Python 3, although no Python worker is started
when `PYFILTER_ENABLED=false`.

Use container paths such as `/certs/service.crt` when configuring certificate
files in the Janus UI.

## Backend configuration precedence

The effective configuration order is:

```text
code defaults
    < .env, or the file selected by ENV_PATH
    < process/container environment
    < DATA_DIR/runtime_config.json for fields managed by the Config page
```

`ENV_PATH` selects the environment file and must be supplied to the process; it
cannot select itself from inside that file. When it is not set, Janus loads
`.env` from the current working directory.

These infrastructure settings are applied at startup only:

- `ENV_PATH`, `DATA_DIR`;
- `API_BIND`, `API_PORT`;
- `TEAM_IP`, `DATA_BIND_MODE`;
- `FLAG_REGEX_CASE_INSENSITIVE`, `FLAG_DECODE_URL`;
- `REDIS_ADDR`, `REDIS_PASSWORD`;
- `PROTO_DIR`;
- `PYFILTER_PYTHON`.

`GOMEMLIMIT` and `GOGC` are read directly by the Go runtime and must be process
or container environment variables.

The **Config** page can update and persist these settings immediately in
`$DATA_DIR/runtime_config.json`:

- team password and flag regex;
- cleanup limits;
- Flag ID integration;
- competition timing, retained rounds, and baseline rounds;
- traffic mode and correlation window;
- deterministic scoring and Python-filter live processing;
- PCAP directory and automatic export.

On the first save from the UI, Janus writes the complete set of UI-managed
fields to `runtime_config.json`. From then on, all fields in that set override
their `.env` equivalents, not only the last edited field.

To return to `.env` values, stop Janus, back up and remove
`data/runtime_config.json`, then start Janus again. This resets Config-page
preferences but does not remove saved services, rules, or traffic.

`DATA_DIR` contains operational state and sensitive data, including a password
saved from the UI. Protect and back it up before updates. Changing the password
in the UI does not revoke existing sessions; restarting Janus invalidates them
because the in-memory signing key is regenerated.

## Updating a native deployment

1. Stop Janus gracefully.
2. Back up the entire `data/` directory, including SQLite, WAL, and JSON files.
3. Download and verify the matching new backend and frontend release artifacts.
4. Extract the new backend into a new directory.
5. Copy the old `.env`, `data/`, `protos/`, and `certs/` into it.
6. Start the new binary with the same launch command used previously.

Keeping each release in its own directory makes rollback quick: stop the new
binary and start the previous one with its preserved data backup.

## Quick troubleshooting

| Symptom                                           | Likely cause                                                                  |
| ------------------------------------------------- | ----------------------------------------------------------------------------- |
| nginx returns 502                                 | VPN/firewall failure, wrong `API_BIND`, or mismatched frontend/backend ports  |
| backend listens on 8080                           | `API_PORT=9090` was not loaded by the process                                 |
| `origin not allowed`                              | reverse proxy did not preserve the `Host` header                              |
| SSE does not update                               | nginx buffering is enabled or the session is not same-origin                  |
| refreshing a frontend route returns 404           | the SPA fallback to `index.html` is missing                                   |
| PCAP import returns 413                           | `client_max_body_size 257m` is missing                                        |
| listener remains `retrying`                       | port is already used, bind IP is not local, or low-port capability is missing |
| PyFilter is `unavailable`                         | Python is absent or `PYFILTER_PYTHON` is incorrect                            |
| a `.env` change is ignored                        | the field is overridden by `runtime_config.json`                              |
| login fails with a quoted password                | quote characters are part of the configured value                             |
| `./janus` loses its data after moving directories | relative `DATA_DIR` points to a different release directory                   |
