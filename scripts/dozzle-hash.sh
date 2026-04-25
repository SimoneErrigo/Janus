#!/usr/bin/env bash
# Generate data/dozzle/users.yml from DOZZLE_PASSWORD in .env.
#
# Usage: ./scripts/dozzle-hash.sh
#
# Run this once on each VM before `docker compose up`. It reads DOZZLE_PASSWORD
# from .env, bcrypt-hashes it via the dozzle image itself (no host deps), and
# writes data/dozzle/users.yml. The file is mounted read-only into the dozzle
# container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.env"
OUT_DIR="$ROOT/data/dozzle"
OUT_FILE="$OUT_DIR/users.yml"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "error: $ENV_FILE not found" >&2
  exit 1
fi

# shellcheck disable=SC1090
PASSWORD="$(grep -E '^DOZZLE_PASSWORD=' "$ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '"' || true)"
if [[ -z "${PASSWORD:-}" ]]; then
  PASSWORD="changeme_dozzle"
  echo "warning: DOZZLE_PASSWORD not set in .env; using default 'changeme_dozzle'" >&2
fi

mkdir -p "$OUT_DIR"

# Use dozzle's built-in generator (subcommand: generate) — avoids needing htpasswd on host.
HASH="$(docker run --rm amir20/dozzle:latest generate --password "$PASSWORD" admin 2>/dev/null | awk '/password:/ {print $2}' | head -n1 || true)"

if [[ -z "${HASH:-}" ]]; then
  # Fallback: use python3 + bcrypt via a throwaway container
  HASH="$(docker run --rm python:3-alpine sh -c "pip install -q bcrypt && python -c \"import bcrypt; print(bcrypt.hashpw(b'$PASSWORD', bcrypt.gensalt()).decode())\"")"
fi

cat > "$OUT_FILE" <<EOF
users:
  admin:
    name: admin
    password: $HASH
EOF

echo "wrote $OUT_FILE (user: admin)"
