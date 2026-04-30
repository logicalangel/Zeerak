# Zeerak

> A lightweight, friendly **web GUI firewall for nftables**.
> Single binary. Safe by default. Plays nicely with Caddy.

**Status:** v0.1 feature-complete on `main`. v0.2 in progress — `zeerak` CLI and `zeerak-mcp` (Model Context Protocol) server are landed; Linux distro packages next. See [VISION.md](VISION.md) for the full plan.

## What it is

Zeerak is a small Go daemon that gives you a clean web UI to manage your Linux host's `nftables` firewall — without the foot-guns. Stage rule changes, preview the diff against the live ruleset, commit with an auto-rollback timer so you can never lock yourself out.

## What it isn't

A full router OS. Use OPNsense/pfSense for that. Zeerak is for the single-VPS / homelab-host / small-team-server case.

## What's working today (v0.1)

- `zeerak-server` daemon — single static Go binary
- HTTP control plane on loopback + unix socket: `/healthz` `/version` `/status` `/ruleset/live` `/preview` `/stage` `/confirm` `/rollback`
- Stage → confirm flow with **auto-rollback timer** (default 30 s)
- Live ruleset read + unified-diff preview (`POST /preview`) before any change touches the kernel
- Presets: "Caddy box", "SSH from my IP" (v4/v6 allowlist), "default deny inbound"
- Hardened `systemd` unit (CAP_NET_ADMIN-only) + example `Caddyfile` reverse-proxy config in [`deploy/`](deploy/)
- Structured JSON logs to `journald` via stderr
- Netns-based test kit wired into CI

## CLI (v0.2)

The `zeerak` CLI talks to a running daemon over its unix socket (or HTTP, via `--addr`). Useful for GitOps and shell scripts:

```sh
zeerak status                           # show stager state
zeerak ruleset                          # dump live nftables ruleset
zeerak preview -f new-config.yaml       # render + diff vs live
zeerak apply   -f new-config.yaml --yes # stage + confirm in one go
zeerak rollback                         # abort a pending stage
```

`--addr` (or env `ZEERAK_ADDR`) accepts either a socket path (default `/run/zeerak/zeerak.sock`) or an `http://host:port` URL.

## MCP server (v0.2)

`zeerak-mcp` exposes the daemon's read-only state to LLM agents via the [Model Context Protocol](https://modelcontextprotocol.io). It serves two resources (`zeerak://status`, `zeerak://ruleset/live`) and two tools (`explain_rule`, `simulate_packet`).

```sh
# stdio — wire into Claude Desktop, mcp-cli, etc.
zeerak-mcp

# HTTP — POST JSON-RPC 2.0 to /mcp
zeerak-mcp --http 127.0.0.1:7879
```

It's strictly read-only in v0; staging tools land in v0.3.

## Quick links

- [VISION.md](VISION.md) — design doc, roadmap, locked decisions (§11)
- [`deploy/`](deploy/) — systemd unit, Caddyfile example, sample configs
- Discussions — _(coming soon)_

## Stack

Go 1.26 · `net/http` (Go 1.22 method routing, no router dep) · `log/slog` · `gopkg.in/yaml.v3` · `nft(8)` shell-out for ruleset apply/read (per VISION §11)

Web UI (v0.2): HTMX + Svelte islands + Tailwind + shadcn-svelte.

No database. The running config is a single YAML file (hand-edit `/etc/zeerak/zeerak.yaml`, or let the UI manage `/var/lib/zeerak/autosave.yaml`) — Caddy-style. Audit lives in `journald`, history lives in `git`.

## License

[Apache-2.0](LICENSE). The **"Zeerak" name and logo are reserved** to the upstream project — see [TRADEMARKS.md](TRADEMARKS.md). Forks welcome; pick your own name.
