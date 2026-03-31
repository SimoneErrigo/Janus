#!/usr/bin/env bash
set -euo pipefail

# Janus manual cleanup script
# Connects to SQLite directly — no running Janus required.
# Usage: ./scripts/cleanup.sh [--max-age-minutes N] [--max-db-size-mb N] [--db-path PATH]

DB_PATH="./data/packets.db"
MAX_AGE_MINUTES=0
MAX_DB_SIZE_MB=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-age-minutes)
            MAX_AGE_MINUTES="$2"
            shift 2
            ;;
        --max-db-size-mb)
            MAX_DB_SIZE_MB="$2"
            shift 2
            ;;
        --db-path)
            DB_PATH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--max-age-minutes N] [--max-db-size-mb N] [--db-path PATH]"
            echo ""
            echo "Options:"
            echo "  --max-age-minutes N   Delete packets older than N minutes (0 = disabled)"
            echo "  --max-db-size-mb N    Delete oldest packets until DB is below N MB (0 = disabled)"
            echo "  --db-path PATH        Path to packets.db (default: ./data/packets.db)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ ! -f "$DB_PATH" ]]; then
    echo "Error: database file not found at $DB_PATH"
    exit 1
fi

if ! command -v sqlite3 &>/dev/null; then
    echo "Error: sqlite3 is required but not found in PATH"
    exit 1
fi

if [[ "$MAX_AGE_MINUTES" -eq 0 && "$MAX_DB_SIZE_MB" -eq 0 ]]; then
    echo "Error: specify at least one of --max-age-minutes or --max-db-size-mb"
    exit 1
fi

echo "=== Janus Cleanup ==="
echo "Database: $DB_PATH"

# Get initial counts
PACKETS_BEFORE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM packets;")
ALERTS_BEFORE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")
SIZE_BEFORE=$(du -m "$DB_PATH" | cut -f1)
echo "Before: $PACKETS_BEFORE packets, $ALERTS_BEFORE alerts, ${SIZE_BEFORE}MB"

# Policy 1: age-based cleanup
if [[ "$MAX_AGE_MINUTES" -gt 0 ]]; then
    CUTOFF=$(date -u -v-"${MAX_AGE_MINUTES}M" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || \
             date -u -d "-${MAX_AGE_MINUTES} minutes" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null)
    if [[ -n "$CUTOFF" ]]; then
        echo "Deleting packets older than $MAX_AGE_MINUTES minutes (before $CUTOFF)..."
        sqlite3 "$DB_PATH" "DELETE FROM alerts WHERE packet_id IN (SELECT id FROM packets WHERE timestamp < '$CUTOFF');"
        sqlite3 "$DB_PATH" "DELETE FROM packets WHERE timestamp < '$CUTOFF';"
    else
        echo "Warning: could not compute cutoff date"
    fi
fi

# Policy 2: size-based cleanup
if [[ "$MAX_DB_SIZE_MB" -gt 0 ]]; then
    echo "Enforcing max DB size: ${MAX_DB_SIZE_MB}MB..."
    while true; do
        CURRENT_SIZE=$(du -m "$DB_PATH" | cut -f1)
        if [[ "$CURRENT_SIZE" -le "$MAX_DB_SIZE_MB" ]]; then
            break
        fi
        REMAINING=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM packets;")
        if [[ "$REMAINING" -eq 0 ]]; then
            break
        fi
        sqlite3 "$DB_PATH" "DELETE FROM alerts WHERE packet_id IN (SELECT id FROM packets ORDER BY timestamp ASC LIMIT 1000);"
        sqlite3 "$DB_PATH" "DELETE FROM packets WHERE id IN (SELECT id FROM packets ORDER BY timestamp ASC LIMIT 1000);"
    done
fi

# Vacuum to reclaim space
echo "Running VACUUM..."
sqlite3 "$DB_PATH" "VACUUM;"

# Get final counts
PACKETS_AFTER=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM packets;")
ALERTS_AFTER=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")
SIZE_AFTER=$(du -m "$DB_PATH" | cut -f1)

echo ""
echo "=== Summary ==="
echo "Packets deleted: $((PACKETS_BEFORE - PACKETS_AFTER))"
echo "Alerts deleted:  $((ALERTS_BEFORE - ALERTS_AFTER))"
echo "Final DB size:   ${SIZE_AFTER}MB (was ${SIZE_BEFORE}MB)"