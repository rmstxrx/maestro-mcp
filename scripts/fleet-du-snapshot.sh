#!/usr/bin/env bash
# fleet-du-snapshot.sh — Weekly disk usage snapshot for fleet health monitoring.
#
# Usage:
#   ./fleet-du-snapshot.sh              # Run on current machine (auto-detects hostname)
#   ./fleet-du-snapshot.sh gpu-server     # Force a specific profile
#
# Output: Appends timestamped entry to ~/.local/share/fleet-du/snapshots.log
# Rotate: Keeps last 52 entries (1 year of weekly snapshots).
#
# Install as cron:
#   crontab -e
#   0 9 * * 1 ~/Development/maestro-mcp/scripts/fleet-du-snapshot.sh
#
# On Win-server (Task Scheduler):
#   powershell -Command "wsl -d Ubuntu -- ~/Development/maestro-mcp/scripts/fleet-du-snapshot.sh win-server"

set -euo pipefail

HOST="${1:-$(hostname -s)}"
LOG_DIR="${HOME}/.local/share/fleet-du"
LOG_FILE="${LOG_DIR}/snapshots.log"
MAX_ENTRIES=52

mkdir -p "$LOG_DIR"

timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== ${HOST} @ ${timestamp} ===" >> "$LOG_FILE"

case "$HOST" in
    gpu-server)
        du -sh ~/Development ~/models ~/.cache ~/.ollama ~/Downloads 2>/dev/null >> "$LOG_FILE" || true
        du -sh ~/Development/*/ 2>/dev/null | sort -rh | head -5 >> "$LOG_FILE" || true
        du -sh ~/models/*/ 2>/dev/null | sort -rh >> "$LOG_FILE" || true
        df -h /home | tail -1 >> "$LOG_FILE"

        # Alerts
        cache_gb=$(du -sb ~/.cache 2>/dev/null | awk '{printf "%.0f", $1/1073741824}')
        models_gb=$(du -sb ~/models 2>/dev/null | awk '{printf "%.0f", $1/1073741824}')
        [ "${cache_gb:-0}" -gt 10 ] && echo "ALERT: ~/.cache is ${cache_gb}GB (threshold: 10GB)" >> "$LOG_FILE"
        [ "${models_gb:-0}" -gt 200 ] && echo "ALERT: ~/models is ${models_gb}GB (threshold: 200GB)" >> "$LOG_FILE"
        ;;

    win-server|WIN-SERVER)
        # Win-server runs this via WSL, reading Windows paths through /mnt/c
        win_dev="/mnt/c/Users/youruser/Development"
        win_dl="/mnt/c/Users/youruser/Downloads"
        du -sh "$win_dev" "$win_dl" 2>/dev/null >> "$LOG_FILE" || true
        du -sh "$win_dev"/*/ 2>/dev/null | sort -rh | head -5 >> "$LOG_FILE" || true
        df -h /mnt/c | tail -1 >> "$LOG_FILE"

        # Alerts
        dl_gb=$(du -sb "$win_dl" 2>/dev/null | awk '{printf "%.0f", $1/1073741824}')
        dev_gb=$(du -sb "$win_dev" 2>/dev/null | awk '{printf "%.0f", $1/1073741824}')
        [ "${dl_gb:-0}" -gt 1 ] && echo "ALERT: Downloads is ${dl_gb}GB (threshold: 1GB)" >> "$LOG_FILE"
        [ "${dev_gb:-0}" -gt 500 ] && echo "ALERT: Development is ${dev_gb}GB (threshold: 500GB)" >> "$LOG_FILE"
        ;;

    macbook|Macbook*|*.local)
        du -sh ~/Development ~/.cache ~/.ollama 2>/dev/null >> "$LOG_FILE" || true
        du -sh ~/Development/*/ 2>/dev/null | sort -rh | head -5 >> "$LOG_FILE" || true
        df -h / | tail -1 >> "$LOG_FILE"

        # Alerts
        cache_gb=$(du -sb ~/.cache 2>/dev/null | awk '{printf "%.0f", $1/1073741824}')
        ollama_gb=$(du -sb ~/.ollama 2>/dev/null | awk '{printf "%.0f", $1/1073741824}')
        [ "${cache_gb:-0}" -gt 5 ] && echo "ALERT: ~/.cache is ${cache_gb}GB (threshold: 5GB)" >> "$LOG_FILE"
        [ "${ollama_gb:-0}" -gt 5 ] && echo "ALERT: ~/.ollama is ${ollama_gb}GB (threshold: 5GB)" >> "$LOG_FILE"
        ;;

    *)
        echo "Unknown host: $HOST" >> "$LOG_FILE"
        du -sh ~/*/ 2>/dev/null | sort -rh | head -10 >> "$LOG_FILE" || true
        df -h / | tail -1 >> "$LOG_FILE"
        ;;
esac

echo "" >> "$LOG_FILE"

# Rotate: keep only last MAX_ENTRIES snapshots
if [ -f "$LOG_FILE" ]; then
    entry_count=$(grep -c "^=== " "$LOG_FILE" || true)
    if [ "$entry_count" -gt "$MAX_ENTRIES" ]; then
        # Find the line number of the (entry_count - MAX_ENTRIES + 1)th entry
        trim_to=$((entry_count - MAX_ENTRIES))
        cut_line=$(grep -n "^=== " "$LOG_FILE" | sed -n "$((trim_to + 1))p" | cut -d: -f1)
        if [ -n "$cut_line" ]; then
            tail -n +"$cut_line" "$LOG_FILE" > "${LOG_FILE}.tmp"
            mv "${LOG_FILE}.tmp" "$LOG_FILE"
        fi
    fi
fi

echo "Snapshot recorded for ${HOST} at ${timestamp}"
