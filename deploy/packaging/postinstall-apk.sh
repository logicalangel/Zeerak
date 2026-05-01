#!/bin/sh
# Alpine post-install. Alpine uses OpenRC, not systemd. The systemd unit is
# still shipped under /lib/systemd for documentation, but here we just create
# the system user and directories.
set -eu

if ! getent group zeerak >/dev/null 2>&1; then
    addgroup -S zeerak
fi
if ! getent passwd zeerak >/dev/null 2>&1; then
    adduser -S -D -H -G zeerak -h /var/lib/zeerak -s /sbin/nologin zeerak
fi

mkdir -p /etc/zeerak /var/lib/zeerak /run/zeerak
chown root:zeerak /etc/zeerak /var/lib/zeerak /run/zeerak || true
chmod 0750 /etc/zeerak /var/lib/zeerak /run/zeerak || true

cat <<'EOF'

Zeerak installed.

Alpine uses OpenRC. A `/etc/init.d/zeerak-server` script is not (yet)
shipped — run the daemon manually for now:

  zeerak-server --config /etc/zeerak/zeerak.yaml

An rc-service unit is tracked for v0.3.
EOF
