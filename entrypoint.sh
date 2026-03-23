#!/bin/bash
set -e

# Copy SSH files with correct permissions (host filesystem may have
# permissive modes that OpenSSH rejects on config/keys).
mkdir -p /root/.ssh/sockets
cp /mnt/ssh/cellar_ed25519 /root/.ssh/cellar_ed25519
cp /mnt/ssh/config          /root/.ssh/config
cp /mnt/ssh/known_hosts     /root/.ssh/known_hosts
chmod 700 /root/.ssh
chmod 600 /root/.ssh/cellar_ed25519 /root/.ssh/config
chmod 644 /root/.ssh/known_hosts

exec "$@"
