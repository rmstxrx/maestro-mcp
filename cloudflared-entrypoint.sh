#!/bin/sh
set -e
mkdir -p /etc/cloudflared
cp /mnt/cloudflared/config.yml /etc/cloudflared/config.yml
cp /mnt/cloudflared/credentials.json /etc/cloudflared/credentials.json
chmod 644 /etc/cloudflared/config.yml
chmod 600 /etc/cloudflared/credentials.json
exec cloudflared "$@"
