# Zeerak — A Lightweight Web GUI Firewall for nftables

> **Zeerak** (زیرک) — *clever, sharp, perceptive* in Persian.
> A small, friendly firewall manager that doesn't get in your way.

---

## 1. Why Zeerak?

Most Linux firewall front-ends fall into two camps:

- **Heavyweight** (pfSense/OPNsense-style appliances) — full OSes, overkill for a single VPS or homelab box.
- **Bare** (`nft`, `iptables`, `ufw`) — powerful but unfriendly; easy to lock yourself out, hard to reason about rule order, no audit trail.

Zeerak aims for the **sweet spot**: a single small binary you drop on a Linux host that gives you a clean web UI to manage **nftables** rules safely, with sensible defaults, presets for common use cases, and tight integration with tools you already use (Caddy, Docker, Tailscale, fail2ban).

### Design principles

1. **Lightweight** — single static Go binary, < 20 MB, no runtime deps beyond `nft`.
2. **Safe by default** — every rule change goes through *staged → preview (diff) → commit with auto-rollback timer*. You can't lock yourself out.
3. **Readable** — the UI shows nftables in human terms *and* shows the generated `nft` ruleset side-by-side. Power users keep their power.
4. **Opinionated presets** — "allow SSH from my IP", "expose Caddy on 80/443", "block country X", "only Tailscale" — one click, fully auditable.
5. **Great DX** — clear API, OpenAPI spec, declarative config file (so it can live in git), `zeerak` CLI mirrors the UI.
6. **Boring tech** — Go + SQLite + server-rendered HTML (HTMX) + a sprinkle of Svelte/Alpine for interactivity. No SPA build hell.

### Non-goals (for v1)

- Not a router/NAT appliance (no DHCP, DNS, VPN server, captive portal).
- Not a multi-host orchestrator (one host, one Zeerak — federate later).
- Not iptables-compatible — nftables only.

---

## 2. Target Users & Use Cases

| Persona | Use case |
|---|---|
| Solo dev with a VPS | Expose Caddy on 80/443, SSH only from home IP, drop everything else. |
| Homelab tinkerer | Segment LAN/IoT/guest, block outbound from IoT, allow Jellyfin from LAN only. |
| Small team / startup | Audit-logged firewall on app servers, GitOps-friendly config, no surprise lockouts. |
| Learner | See the UI choice → see the generated `nft` rule. Learn nftables by doing. |

### Concrete v1 scenarios

- **"Caddy box"**: allow 22 (from my IP), 80, 443; drop everything else; log drops.
- **"Docker host"**: integrate cleanly with Docker's nftables chains without fighting them.
- **"Wireguard/Tailscale-only admin"**: SSH only reachable over the tunnel.
- **"Country block"**: drop traffic from a list of CIDRs (ipset-backed, auto-updated).
- **"Rate-limit SSH"**: 5 attempts/min/IP, drop excess.

---

## 3. Architecture (proposed)

```
┌─────────────────────────────────────────────┐
│  Browser (HTMX + Svelte islands + Tailwind) │
└──────────────────┬──────────────────────────┘
                   │ HTTPS (via Caddy reverse proxy)
┌──────────────────▼──────────────────────────┐
│  zeerak-server (single Go binary)           │
│  ├── HTTP API (chi/echo) + HTMX views       │
│  ├── Auth (local users + optional OIDC)     │
│  ├── Rule engine                            │
│  │     model → validator → nft renderer     │
│  ├── Stager (apply with auto-rollback)      │
│  ├── Audit log (append-only, SQLite)        │
│  └── Integrations: Caddy, Docker, Tailscale │
└──────────────────┬──────────────────────────┘
                   │ netlink / `nft -j`
┌──────────────────▼──────────────────────────┐
│  Linux kernel — nftables                    │
└─────────────────────────────────────────────┘
```

### Stack

- **Language**: Go (chosen — single static binary, great for sysadmin tooling).
- **Web**: server-rendered HTML + [HTMX](https://htmx.org) for interactivity, small Svelte islands for the rule editor / live diff.
- **Styling**: Tailwind CSS.
- **Storage**: SQLite (config, users, audit log). Rule model is the source of truth; nftables is *rendered* from it.
- **nftables interface**: prefer [`google/nftables`](https://github.com/google/nftables) (netlink) for reads & atomic transactions; shell out to `nft -f -` as a fallback for human-readable apply.
- **Auth**: local password (argon2id) + TOTP; optional OIDC (so it works behind Caddy's `forward_auth`).
- **API**: REST + OpenAPI 3.1 spec generated from code.
- **CLI**: `zeerak` binary speaks the same API (handy for scripts & GitOps).

### Repo layout (initial sketch)

```
zeerak/
├── cmd/
│   ├── zeerak-server/      # daemon
│   └── zeerak/             # CLI
├── internal/
│   ├── model/              # Rule, Chain, Set, Policy types
│   ├── render/             # model → nft ruleset
│   ├── nft/                # netlink + `nft` shell adapter
│   ├── stager/             # stage → preview → commit → rollback
│   ├── audit/              # append-only log
│   ├── auth/
│   ├── api/                # HTTP handlers + OpenAPI
│   ├── ui/                 # HTMX templates, Svelte islands
│   └── integrations/
│       ├── caddy/
│       ├── docker/
│       └── tailscale/
├── web/                    # Tailwind + Svelte source
├── deploy/
│   ├── systemd/
│   ├── caddy/              # example Caddyfile
│   └── docker/
├── docs/
└── VISION.md               # this file
```

---

## 4. Safety: the "auto-rollback" pattern

The single biggest fear with a remote firewall UI is **locking yourself out**. Zeerak's apply flow:

1. **Stage** changes — edited in DB, not applied.
2. **Preview** — UI shows a unified diff of the rendered `nft` ruleset, plus a plain-English summary ("This will block port 22 from 0.0.0.0/0").
3. **Commit with armed rollback** — apply the new ruleset *and* schedule a revert in **N seconds** (default 60).
4. **Confirm** — user must click "Keep changes" from the (still-reachable) browser within the window, or Zeerak rolls back automatically.

This is borrowed from Mikrotik's "safe mode" and from `iptables-apply`. It should be the default for *every* destructive change.

---

## 5. Caddy Integration (you asked for both 🎯)

Two complementary modes:

### A. Caddy in front of Zeerak (recommended deployment)

- Caddy terminates TLS and reverse-proxies to `zeerak-server` on `127.0.0.1:7878`.
- Zeerak ships an example `Caddyfile`:
  ```caddyfile
  zeerak.example.com {
      reverse_proxy 127.0.0.1:7878
      # optional: SSO via Authelia / Authentik
      # forward_auth ...
  }
  ```
- Zeerak's UI never has to deal with TLS itself. Simpler, safer.

### B. Zeerak manages Caddy config

- A "Caddy" panel in the UI lets you:
  - See current sites, certs, and upstream targets (read from Caddy's admin API at `localhost:2019`).
  - One-click create matching firewall rules: *"Caddy listens on 80/443 → ensure inbound 80/443 are allowed"*.
  - Warn if firewall blocks a port Caddy is bound to (very common footgun).
- Optional: edit Caddyfile through Zeerak with the same stage→preview→commit flow.

Both modes are **opt-in** and decoupled: you can use A without B.

---

## 6. Other integrations (post-v1, planned)

- **Docker**: detect Docker's `DOCKER` and `DOCKER-USER` chains, surface them, let you add rules to `DOCKER-USER` safely.
- **Tailscale**: detect `tailscale0`, presets like *"admin services only on tailnet"*.
- **fail2ban / CrowdSec**: visualize their bans, allow Zeerak to manage the underlying nft sets directly.
- **GeoIP / threat feeds**: scheduled-updated nft sets from MaxMind / Spamhaus / Firehol.

---

## 7. Roadmap

### v0.1 — "It works on my VPS"
- [ ] Project scaffold, CI, single binary build
- [ ] Read current nftables ruleset, render in UI (read-only)
- [ ] Rule model + renderer + round-trip tests
- [ ] Auth (local user, argon2id, TOTP)
- [ ] Stage → preview (diff) → commit-with-rollback
- [ ] Presets: "Caddy box", "SSH from my IP", "default deny inbound"
- [ ] Audit log
- [ ] Caddyfile example + systemd unit

### v0.2 — Integrations
- [ ] Caddy admin-API panel (read-only first, then write)
- [ ] Docker chain awareness
- [ ] CLI (`zeerak apply -f config.yaml`) — GitOps-friendly
- [ ] OpenAPI spec + generated client

### v0.3 — Power features
- [ ] Named sets/maps editor (CIDR lists, country blocks)
- [ ] Rate-limiting / connection-tracking rule helpers
- [ ] Tailscale + WireGuard awareness
- [ ] OIDC / `forward_auth`

### Later
- [ ] IPv6 parity audit
- [ ] Multi-host (read-only fleet view first)
- [ ] Plugin system for custom presets

---

## 8. Open questions (let's discuss)

1. **Rule model**: do we expose nftables 1:1 (chains, hooks, priorities, verdicts) or invent a higher-level "policy" abstraction and render down? *Proposal: higher-level model for the UI, but always show & allow editing the raw `nft` per chain.*
2. **Distro support**: target Debian/Ubuntu + Fedora + Arch first? Alpine (musl) for containers?
3. **Packaging**: `.deb`/`.rpm` + a one-liner installer (`curl … | sh`) + Docker image? Homebrew tap for the CLI?
4. **License**: Apache-2.0 or AGPL-3.0? AGPL protects against closed-source SaaS forks; Apache is friendlier for adoption.
5. **Name conflicts**: quick check needed on PyPI/GitHub/crates for "zeerak" collisions before we get attached.
6. **Telemetry**: opt-in only, or none at all in v1? *Proposal: none in v1.*
7. **Multi-tenant / RBAC**: punt to v0.3+? *Proposal: yes — single admin user in v0.1.*

---

## 9. Inspirations & prior art

- **firewalld** — zone model is nice; XML config is not.
- **ufw** — simplicity goal; but CLI-only and iptables-era.
- **OPNsense / pfSense** — feature-rich; way too heavy for our target.
- **Mikrotik RouterOS "safe mode"** — auto-rollback UX we're cribbing.
- **Caddy** — DX north star: one binary, sensible defaults, great docs.
- **Tailscale admin panel** — clean, focused UI we admire.

---

## 10. How to contribute to *this document*

This file is the living design doc. PRs welcome. If you disagree with a design choice, open an issue with a "Decision proposal" — we'll discuss in the open and record the outcome in `docs/decisions/` (lightweight ADRs).
