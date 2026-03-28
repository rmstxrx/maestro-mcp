#!/bin/sh
set -e
mkdir -p /etc/cloudflared
cp /mnt/cloudflared/config.yml /etc/cloudflared/config.yml
cp /mnt/cloudflared/credentials.json /etc/cloudflared/credentials.json
chmod 644 /etc/cloudflared/config.yml
chmod 600 /etc/cloudflared/credentials.json

# Watchdog: detect stale network namespace after maestro daemon auto-restart.
# (Compose-initiated restarts are handled by depends_on.restart: true.)
# If maestro is unreachable for 3 consecutive checks (30s), exit so Docker's
# restart policy re-creates this container with maestro's fresh namespace.
(
  sleep 30  # grace period for initial startup
  fails=0
  while true; do
    sleep 10
    if wget -q -O /dev/null --timeout=5 http://localhost:8222/.well-known/oauth-authorization-server 2>/dev/null; then
      fails=0
    else
      fails=$((fails + 1))
    fi
    if [ "$fails" -ge 3 ]; then
      echo "watchdog: maestro unreachable for 30s, exiting to re-attach network namespace" >&2
      kill 1
      exit 1
    fi
  done
) &

exec cloudflared "$@"
