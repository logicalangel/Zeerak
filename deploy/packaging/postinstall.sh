#!/bin/sh
# Post-install (deb / rpm): reload systemd, suggest enabling the unit.
# We deliberately do NOT enable / start zeerak-server automatically — the
# operator should review /etc/zeerak/zeerak.yaml first. Auto-starting a
# firewall daemon on package install is exactly how you get locked out.
set -eu

if [ -d /etc/zeerak ]; then
    chown root:zeerak /etc/zeerak || true
    chmod 0750 /etc/zeerak || true
fi
if [ -f /etc/zeerak/zeerak.yaml ]; then
    chown root:zeerak /etc/zeerak/zeerak.yaml || true
    chmod 0640 /etc/zeerak/zeerak.yaml || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    cat <<'EOF'

Zeerak installed. The daemon is NOT enabled or started automatically.

  1. Review and edit  /etc/zeerak/zeerak.yaml
  2. Enable + start:  sudo systemctl enable --now zeerak-server
  3. Check status:    zeerak status
  4. Web panel:       http://127.0.0.1:7878/

Reverse-proxy auth is the operator's responsibility (see the example
Caddyfile under /usr/share/doc/zeerak/).
EOF
fi
