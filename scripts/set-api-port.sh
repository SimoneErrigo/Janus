#!/usr/bin/env bash
#
# set-api-port.sh — change the Janus backend API port everywhere it matters.
#
# Updates, in one shot and consistently:
#   - .env                          (API_PORT=...)            [only if it exists]
#   - docker-compose.yml            (API_PORT=...)
#   - docker-compose-competition.yml (API_PORT=...)
#   - frontend/nginx.conf           (proxy_pass ...:<port>)   [both /api locations]
#   - frontend/vite.config.js       (dev proxy '/api' target)
#
# Replacements are anchored to those specific patterns, so unrelated 8080s
# (e.g. a sample dst_port in the UI) are never touched.
#
# Usage:
#   scripts/set-api-port.sh <new_port>
#   scripts/set-api-port.sh 9090
#
# After running, rebuild/restart so the change takes effect:
#   docker compose up -d --build
#
set -euo pipefail

# --- resolve paths (works from anywhere) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- args ---
if [ $# -ne 1 ]; then
  echo "usage: $(basename "$0") <new_port>" >&2
  exit 2
fi
NEW_PORT="$1"

if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
  echo "error: '$NEW_PORT' is not a valid port (1-65535)" >&2
  exit 2
fi

# --- portable in-place sed (BSD/macOS + GNU/Linux) ---
sed_inplace() {
  local expr="$1" file="$2" tmp
  tmp="$(mktemp)"
  sed -E "$expr" "$file" > "$tmp" && mv "$tmp" "$file"
}

# Detect the current port for a friendly summary (best-effort).
current_port() {
  local f
  for f in "$ROOT/.env" "$ROOT/docker-compose.yml"; do
    if [ -f "$f" ]; then
      local p
      p="$(sed -nE 's/^[[:space:]]*-?[[:space:]]*API_PORT=([0-9]+).*/\1/p' "$f" | head -n1)"
      if [ -n "$p" ]; then echo "$p"; return; fi
    fi
  done
  echo "8080"
}

CUR="$(current_port)"
echo "Setting Janus API port: $CUR -> $NEW_PORT"
if [ "$CUR" = "$NEW_PORT" ]; then
  echo "(already $NEW_PORT — re-applying to be safe)"
fi

changed=0

# API_PORT=<n>  in .env and both compose files
for f in ".env" "docker-compose.yml" "docker-compose-competition.yml"; do
  path="$ROOT/$f"
  if [ -f "$path" ] && grep -qE '^[[:space:]]*-?[[:space:]]*API_PORT=' "$path"; then
    sed_inplace "s/^([[:space:]]*-?[[:space:]]*API_PORT=)[0-9]+/\1$NEW_PORT/" "$path"
    echo "  updated $f (API_PORT)"
    changed=$((changed + 1))
  fi
done

# nginx: proxy_pass http://${API_BACKEND}:<port>;  (two locations)
NGINX="$ROOT/frontend/nginx.conf"
if [ -f "$NGINX" ] && grep -qE 'proxy_pass[[:space:]]+http://\$\{API_BACKEND\}:[0-9]+' "$NGINX"; then
  sed_inplace "s|(proxy_pass[[:space:]]+http://\\\$\{API_BACKEND\}:)[0-9]+|\1$NEW_PORT|g" "$NGINX"
  echo "  updated frontend/nginx.conf (proxy_pass)"
  changed=$((changed + 1))
fi

# vite dev proxy: '/api': 'http://localhost:<port>'
VITE="$ROOT/frontend/vite.config.js"
if [ -f "$VITE" ] && grep -qE "'/api':[[:space:]]*'http://localhost:[0-9]+'" "$VITE"; then
  sed_inplace "s|('/api':[[:space:]]*'http://localhost:)[0-9]+'|\1$NEW_PORT'|" "$VITE"
  echo "  updated frontend/vite.config.js (dev proxy)"
  changed=$((changed + 1))
fi

echo
if [ "$changed" -eq 0 ]; then
  echo "Nothing changed — no matching files/patterns found under $ROOT"
  exit 1
fi

echo "Done ($changed file(s) updated)."
echo "Next:"
echo "  - Docker:  docker compose up -d --build"
echo "  - Local dev: restart the backend so it binds :$NEW_PORT (API_PORT), and the vite dev server."
echo "  - Helper scripts talking to the API: export JANUS_URL=http://localhost:$NEW_PORT"
