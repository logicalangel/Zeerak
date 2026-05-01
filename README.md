# Zeerak

> A lightweight, friendly **web GUI firewall for nftables**.
> Single binary. Safe by default. Plays nicely with Caddy.

**Status:** v0.1 feature-complete on `main`. v0.2 in progress — `zeerak` CLI, `zeerak-mcp` (Model Context Protocol) server, web panel + preset wizard, and public packaging (deb/rpm/apk/AUR/Homebrew/GHCR) are landed. See [VISION.md](VISION.md) for the full plan.

## What it is

Zeerak is a small Go daemon that gives you a clean web UI to manage your Linux host's `nftables` firewall — without the foot-guns. Stage rule changes, preview the diff against the live ruleset, commit with an auto-rollback timer so you can never lock yourself out.

## What it isn't

A full router OS. Use OPNsense/pfSense for that. Zeerak is for the single-VPS / homelab-host / small-team-server case.

## What's working today (v0.1)

- `zeerak-server` daemon — single static Go binary
- HTTP control plane on loopback + unix socket: `/healthz` `/version` `/status` `/ruleset/live` `/preview` `/stage` `/confirm` `/rollback`
- Stage → confirm flow with **auto-rollback timer** (default 60 s)
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

## Install

Pre-built packages ship for every `v*` tag — pick the one that matches your distro:

```sh
# Debian / Ubuntu (PPA)
sudo add-apt-repository ppa:logicalangel/zeerak
sudo apt update && sudo apt install zeerak

# Fedora / RHEL (COPR)
sudo dnf copr enable logicalangel/zeerak
sudo dnf install zeerak

# Arch (AUR)
yay -S zeerak-bin            # or: paru -S zeerak-bin

# Alpine — grab the .apk from GitHub Releases
sudo apk add --allow-untrusted zeerak_<ver>_linux_amd64.apk

# Homebrew (macOS or Linuxbrew, CLI only on macOS)
brew install logicalangel/zeerak/zeerak

# Container (multi-arch)
docker pull ghcr.io/logicalangel/zeerak:latest
```

After install on a systemd distro:

```sh
sudo systemctl enable --now zeerak-server
zeerak status
xdg-open http://127.0.0.1:7878/
```

The PPA, COPR, and AUR repos are first-party but operator-uploaded per release — see [`deploy/PACKAGING.md`](deploy/PACKAGING.md). The deb / rpm / apk / GHCR image / Homebrew formula publish automatically from the [release workflow](.github/workflows/release.yml).

## Getting started (from source)

> Zeerak is a Linux-only daemon (it shells out to `nft(8)`). On macOS / Windows, use the bundled Docker setup — see [Try it in Docker](#try-it-in-docker).

### 1. Build

```sh
git clone https://github.com/logicalangel/Zeerak.git
cd Zeerak
go build -o out/ ./cmd/...
# produces out/zeerak-server, out/zeerak, out/zeerak-mcp
```

### 2. Configure

Drop a config at `/etc/zeerak/zeerak.yaml`. Start from the bundled examples:

```sh
sudo install -d -m 0755 /etc/zeerak
sudo cp deploy/examples/zeerak.yaml /etc/zeerak/zeerak.yaml
sudoedit /etc/zeerak/zeerak.yaml      # set your SSH allowlist, presets, etc.
```

Minimal config (default-deny inbound, allow SSH from anywhere, allow Caddy on 80/443):

```yaml
version: 1
server:
  listen: "127.0.0.1:7878"
  socket: "/run/zeerak/zeerak.sock"
  rollback_seconds: 60
presets:
  default_deny_inbound: true
  ssh:
    port: 22
  caddy_box: true
```

### 3. Run the daemon

For development on a Linux host (foreground, requires `CAP_NET_ADMIN` — easiest is `sudo`):

```sh
sudo ./out/zeerak-server --config /etc/zeerak/zeerak.yaml
```

For production, install the hardened systemd unit:

```sh
sudo cp deploy/systemd/zeerak-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zeerak-server
journalctl -u zeerak-server -f         # structured JSON logs
```

### 4. Drive it with the CLI

```sh
# Confirm the daemon is up.
zeerak status

# See what the kernel is actually running.
zeerak ruleset

# Edit your config, then preview the diff *before* it touches the kernel.
$EDITOR /etc/zeerak/zeerak.yaml
zeerak preview -f /etc/zeerak/zeerak.yaml

# Apply with the auto-rollback safety net:
zeerak apply -f /etc/zeerak/zeerak.yaml          # stages — you have rollback_seconds to confirm
zeerak confirm                                   # keep changes
# ...or do nothing and the daemon reverts automatically.

# Skip the two-step prompt (CI / GitOps):
zeerak apply -f /etc/zeerak/zeerak.yaml --yes

# Bail out of a pending stage immediately:
zeerak rollback
```

`--addr` (or env `ZEERAK_ADDR`) overrides the daemon address — use a unix socket path or an `http://host:port` URL.

### 5. Open the web panel (optional)

The daemon also serves a minimal web panel on the same port:

```
http://127.0.0.1:7878/
```

- **`/`** — dashboard with current status, pending-change banner, and Confirm / Rollback buttons.
- **`/presets`** — preset wizard: pick `default_deny_inbound`, `caddy_box`, or an SSH allowlist; see a full unified diff vs the live ruleset before staging.
- **`/ruleset`** — read-only view of `nft list ruleset`.

The panel never bypasses the safety bar: every change goes through the same stage → confirm-or-auto-rollback flow as the CLI and API. (HTMX + Svelte islands + shadcn-svelte and the rule-by-rule designer arrive in v0.3.)

### 6. Talk to it from your AI assistant (optional)

Wire `zeerak-mcp` into any MCP-aware client. Example Claude Desktop entry (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "zeerak": {
      "command": "/usr/local/bin/zeerak-mcp",
      "args": ["--addr", "/run/zeerak/zeerak.sock"]
    }
  }
}
```

The assistant can then read `zeerak://status` / `zeerak://ruleset/live` and call `explain_rule` / `simulate_packet`. It cannot mutate anything in v0.

### Try it in Docker

A `Dockerfile` and `docker-compose.yml` ship in the repo for non-Linux hosts and quick experimentation:

```sh
docker compose up --build -d
docker exec zeerak wget -qO- http://127.0.0.1:7878/healthz   # → {"status":"ok"}
docker exec zeerak zeerak status
```

Edit `deploy/examples/zeerak.yaml` on the host (it's mounted read-only into the container) and `docker compose restart` to pick up changes.

### HTTP API (advanced)

If you'd rather skip the CLI:

```sh
SOCK=/run/zeerak/zeerak.sock
curl --unix-socket $SOCK http://localhost/status
curl --unix-socket $SOCK http://localhost/ruleset/live
curl --unix-socket $SOCK -H 'Content-Type: application/x-yaml' \
     --data-binary @new-config.yaml http://localhost/preview
```

## Quick links

- [VISION.md](VISION.md) — design doc, roadmap, locked decisions (§11)
- [`deploy/`](deploy/) — systemd unit, Caddyfile example, sample configs
- Discussions — _(coming soon)_

## Stack

Go 1.26 · `net/http` (Go 1.22 method routing, no router dep) · `log/slog` · `gopkg.in/yaml.v3` · `nft(8)` shell-out for ruleset apply/read (per VISION §11)

Web UI today: server-rendered Go `html/template`, no JS build step. HTMX + Svelte islands + Tailwind + shadcn-svelte arrive in v0.3 with the rule-by-rule designer.

No database. The running config is a single YAML file (hand-edit `/etc/zeerak/zeerak.yaml`, or let the UI manage `/var/lib/zeerak/autosave.yaml`) — Caddy-style. Audit lives in `journald`, history lives in `git`.

## License

[Apache-2.0](LICENSE). The **"Zeerak" name and logo are reserved** to the upstream project — see [TRADEMARKS.md](TRADEMARKS.md). Forks welcome; pick your own name.
