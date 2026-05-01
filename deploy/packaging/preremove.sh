#!/bin/sh
# Pre-remove: stop + disable the unit cleanly so we don't leave a half-loaded
# nftables ruleset on uninstall.
set -eu

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop zeerak-server.service >/dev/null 2>&1 || true
    systemctl disable zeerak-server.service >/dev/null 2>&1 || true
fi
