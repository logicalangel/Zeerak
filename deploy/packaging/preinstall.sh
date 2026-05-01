#!/bin/sh
# Pre-install: ensure the zeerak system user/group exist before files are
# unpacked so the systemd unit's User=zeerak resolves on first start.
set -eu

if ! getent group zeerak >/dev/null 2>&1; then
    groupadd --system zeerak
fi
if ! getent passwd zeerak >/dev/null 2>&1; then
    useradd --system \
        --gid zeerak \
        --home-dir /var/lib/zeerak \
        --shell /usr/sbin/nologin \
        --comment "Zeerak nftables panel" \
        zeerak
fi
