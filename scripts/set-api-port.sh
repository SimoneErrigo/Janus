#!/usr/bin/env bash
#
# set-api-port.sh — change the Janus backend API port everywhere it matters.
#
# Updates, in one shot and consistently:
#   - .env                          (API_PORT=...)            [only if it exists]
#   - .env.example                  (API_PORT=...)
#   - docker-compose.yml            (API_PORT=...)
#   - docker-compose-competition.yml (API_PORT=...)
#   - backend/Dockerfile             (standalone image API_PORT=...)
#   - frontend runtime proxy env    (API_BACKEND_PORT=...)
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
  # Keep the temporary file beside the destination so the final rename is
  # atomic, and copy metadata before truncating it so modes do not become 0600.
  tmp="$(mktemp "${file}.tmp.XXXXXX")"
  if ! cp -p "$file" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if sed -E "$expr" "$file" > "$tmp" && mv "$tmp" "$file"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
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
  echo "9090"
}

CUR="$(current_port)"
echo "Setting Janus API port: $CUR -> $NEW_PORT"
if [ "$CUR" = "$NEW_PORT" ]; then
  echo "(already $NEW_PORT — re-applying to be safe)"
fi

changed=0

# API_PORT=<n>  in .env and both compose files
for f in ".env" ".env.example" "docker-compose.yml" "docker-compose-competition.yml"; do
  path="$ROOT/$f"
  if [ -f "$path" ] && grep -qE '^[[:space:]]*-?[[:space:]]*API_PORT=' "$path"; then
    sed_inplace "s/^([[:space:]]*-?[[:space:]]*API_PORT=)[0-9]+/\1$NEW_PORT/" "$path"
    echo "  updated $f (API_PORT)"
    changed=$((changed + 1))
  fi
done

BACKEND_DOCKERFILE="$ROOT/backend/Dockerfile"
if [ -f "$BACKEND_DOCKERFILE" ] && grep -qE '^ENV[[:space:]]+API_PORT=' "$BACKEND_DOCKERFILE"; then
  sed_inplace "s/^(ENV[[:space:]]+API_PORT=)[0-9]+/\1$NEW_PORT/" "$BACKEND_DOCKERFILE"
  echo "  updated backend/Dockerfile (API_PORT)"
  changed=$((changed + 1))
fi

# Frontend proxy port in Compose and in the image's standalone default.
for f in "docker-compose.yml" "docker-compose-competition.yml"; do
  path="$ROOT/$f"
  if [ -f "$path" ] && grep -qE '^[[:space:]]*-[[:space:]]*API_BACKEND_PORT=' "$path"; then
    sed_inplace "s/^([[:space:]]*-[[:space:]]*API_BACKEND_PORT=)[0-9]+/\1$NEW_PORT/" "$path"
    echo "  updated $f (API_BACKEND_PORT)"
    changed=$((changed + 1))
  fi
done

FRONTEND_DOCKERFILE="$ROOT/frontend/Dockerfile"
if [ -f "$FRONTEND_DOCKERFILE" ] && grep -qE '^ENV[[:space:]]+API_BACKEND_PORT=' "$FRONTEND_DOCKERFILE"; then
  sed_inplace "s/^(ENV[[:space:]]+API_BACKEND_PORT=)[0-9]+/\1$NEW_PORT/" "$FRONTEND_DOCKERFILE"
  echo "  updated frontend/Dockerfile (API_BACKEND_PORT)"
  changed=$((changed + 1))
fi

# Vite dev proxy (accept both historical localhost and current 127.0.0.1).
VITE="$ROOT/frontend/vite.config.js"
if [ -f "$VITE" ] && grep -qE "target:[[:space:]]*'http://(localhost|127\\.0\\.0\\.1):[0-9]+'" "$VITE"; then
  sed_inplace "s@(target:[[:space:]]*'http://(localhost|127\\.0\\.0\\.1):)[0-9]+'@\1$NEW_PORT'@" "$VITE"
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
