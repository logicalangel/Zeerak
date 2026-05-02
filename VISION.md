# Zeerak — A Lightweight Web GUI Firewall for nftables

> **Zeerak** (زیرک) — _clever, sharp, perceptive_ in Persian.
> A small, friendly firewall manager that doesn't get in your way.

---

## 1. Why Zeerak?

Most Linux firewall front-ends fall into two camps:

- **Bare** (`nft`, `iptables`, `ufw`) — powerful but unfriendly; easy to lock yourself out, hard to reason about rule order.

Zeerak aims for the **sweet spot**: a single small binary you drop on a Linux host that gives you a clean web UI to manage **nftables** rules safely, with sensible defaults, presets for common use cases, and tight integration with tools you already use (Caddy, Docker, Tailscale, NATS, fail2ban).

### Design principles

1. **Lightweight** — single static Go binary, < 15 MB, no runtime deps beyond `nft`.
2. **No database, no user system** — like Caddy. A single config file (`zeerak.yaml`) is the source of truth. Auth is offloaded to a reverse proxy or a unix socket.
3. **Use the OS** — audit lives in `journald`, history lives in `git`, secrets live in the filesystem. Don't reinvent what Linux already does well.
4. **Safe by default** — every rule change goes through _staged → preview (diff) → commit with auto-rollback timer_. You can't lock yourself out.
5. **Readable** — the UI shows nftables in human terms _and_ shows the generated `nft` ruleset side-by-side. Power users keep their power.
6. **Opinionated presets** — "allow SSH from my IP", "expose Caddy on 80/443", "block country X", "only Tailscale" — one click.
7. **Great DX** — clear API, OpenAPI spec, declarative config (so it can live in git), `zeerak` CLI mirrors the UI.
8. **Boring tech** — Go + server-rendered HTML (`html/template`) + a sprinkle of vanilla JS. No SPA build hell.
9. **Open source, easy to install** — 100% open-source on GitHub, developed in the open. Distributed through standard public channels (PPA, COPR, AUR, Alpine, Homebrew, GHCR) so a single `apt install zeerak` / `dnf install zeerak` / `brew install zeerak` _just works_ — no curl-pipe-bash required. (See README for the install matrix.)

### Open source

Zeerak is **open source from day one** under **Apache-2.0**, developed in public on GitHub. Issues, design discussions, and roadmap live in the repo. The Apache-2.0 license is OSI-approved, free forever for personal and commercial use — but the **"Zeerak" name and logo are reserved** to the upstream project (see `TRADEMARKS.md`). Forks are welcome; they just need to pick their own name.

### In scope: anything nftables does natively

If `man nft` documents it, Zeerak aims to surface it. That includes:

- **NAT** — SNAT, DNAT, masquerade, redirect (the classic "router box" / port-forward case).
- **Port forwarding** — DNAT to internal hosts with sensible hook/priority defaults so you don't have to guess.
- **Policy routing marks** — `meta mark set`, `ct mark` for fwmark-based routing, QoS, or split-tunnel VPN.
- **Connection tracking** — `ct state`, conntrack helpers (FTP, SIP, …), zones, ct timeouts.
- **Rate limiting & quotas** — `limit rate`, `quota`, per-IP buckets (already partly shipped for SSH).
- **Sets, maps, intervals, vmaps** — first-class editor for CIDR lists, country blocks, port→verdict maps.
- **Logging & accounting** — `log`, `counter`, named counters surfaced in the UI.

The UI may not expose every knob in v1, but nothing is excluded by design.

### Non-goals (for v1)

- Not a full router OS — Zeerak does not _run_ DHCP, DNS, VPN servers, or captive portals (those are application daemons like `dnsmasq`, `kea`, `wireguard`, `coova-chilli`). Zeerak happily firewalls and NATs _for_ them, and detects them as integrations (§6), but it does not bundle them.
- Not a heavyweight fleet orchestrator — cluster mode (§4) is intentionally simple master/agent config distribution, not a SaaS control plane.
- Not iptables-compatible — nftables only.

---

### Concrete v1 scenarios

- **"Caddy box"**: allow 22 (from my IP), 80, 443; drop everything else; log drops.
- **"Docker host"**: integrate cleanly with Docker's nftables chains without fighting them.
- **"Wireguard/Tailscale-only admin"**: SSH only reachable over the tunnel.
- **"Country block"**: drop traffic from a list of CIDRs (ipset-backed, auto-updated).
- **"Rate-limit SSH"**: 5 attempts/min/IP, drop excess.
- **"Locked-down egress"**: outbound default-deny with an allowlist (DNS, NTP, HTTPS, package mirrors) — catches malware phone-home and accidental data exfil.
- **"Home router box"**: SNAT/masquerade on the WAN interface, DNAT `:443` and `:80` to an internal Caddy host, hairpin NAT for LAN clients hitting the public IP.
- **"Split-tunnel marks"**: tag traffic to specific destinations with `meta mark` so a sibling routing table sends it over WireGuard while the rest goes out the default gateway.

---

## 3. Safety: the "auto-rollback" pattern

The single biggest fear with a remote firewall UI is **locking yourself out**. Zeerak's apply flow:

1. **Stage** changes — edited in DB, not applied.
2. **Preview** — UI shows a unified diff of the rendered `nft` ruleset, plus a plain-English summary ("This will block port 22 from 0.0.0.0/0").
3. **Commit with armed rollback** — apply the new ruleset _and_ schedule a revert in **N seconds** (default 60).
4. **Confirm** — user must click "Keep changes" from the (still-reachable) browser within the window, or Zeerak rolls back automatically.

This is borrowed from Mikrotik's "safe mode" and from `iptables-apply`. It should be the default for _every_ destructive change.

---

## 4. Cluster mode — master/agent config distribution

For users with more than one host (small fleets, edge boxes, multiple VPSes), Zeerak ships a simple **master/agent** model. It is **opt-in**; a stand-alone Zeerak knows nothing about it.

### Topology

```
           ┌──────────────────────────┐
           │  zeerak-server (master)  │  ← UI lives here, single source of truth
           │   /etc/zeerak/cluster/   │     (per-host configs in git)
           └────┬─────────┬─────────┬─┘
       SSH push │   SSH   │   SSH   │     (operator's existing keys / ssh-agent)
           ┌────▼───┐ ┌───▼────┐ ┌──▼─────┐
           │ agent1 │ │ agent2 │ │ agent3 │   ← `zeerak-server --agent`
           └────────┘ └────────┘ └────────┘     thin, headless, no UI
```

- **Master** holds the canonical config tree (`/etc/zeerak/cluster/<host>.yaml` + shared `groups/*.yaml`), the UI, and the API.
- **Agents** run the same binary in `--agent` mode: no UI, just config-receive + apply + report.
- **Transport: SSH-first** (like Ansible). The master reaches agents over **OpenSSH using the operator's existing keys** — `~/.ssh/id_*`, `ssh-agent`, `~/.ssh/config` host aliases, jump hosts, all of it. No new PKI, no cert rotation, no extra ports to open. The agent is just `zeerak-server --agent` invoked over SSH; the channel is whatever SSH negotiates (keys, MFA, FIDO2 keys, agent-forwarding, you name it). mTLS is available as an **opt-in fallback** for environments without SSH (e.g. distroless containers).
- **Authorization**: each agent host trusts a specific principal/key (standard `~/.ssh/authorized_keys` with `command="zeerak-server --agent ..."` and `restrict` options). Removing an agent = removing one line from `authorized_keys`.
- **Two sync modes**, pick per-agent:
  - **Pull** (default, firewall-friendly): agent runs as a small daemon, periodically `ssh master "zeerak cluster pull <host>"` to fetch its rendered config, applies via the same stage→preview→commit→rollback flow.
  - **Push**: master `ssh agent "zeerak-server --agent apply"` and pipes the rendered config over stdin. Useful for ad-hoc "sync now" from the UI.
- **Same safety guarantees**: every push to an agent is staged with the auto-rollback timer. If the master loses contact within the window, the agent rolls back. _No remote lockouts._
- **Groups & inheritance**: an agent's effective config = `defaults.yaml` + `groups/<group>.yaml` + `<host>.yaml`, merged deterministically. Render once on master, ship the rendered artifact + a hash; agents verify hash before apply.
- **Read-only fleet view** in the UI: status per host (last-sync, last-apply, drift), with one-click "sync now" and "show diff vs running".
- **Drift detection**: agents periodically compare running nftables ruleset to the expected hash and report drift to master.
- **Bring-your-own transport**: SSH already covers Tailscale / WireGuard / VPN / bastion-jump scenarios — just point `~/.ssh/config` at the right address.

### Non-goals for cluster v1

- No HA / multi-master (one master, period). Backup the config dir; that's your DR.
- No leader election, no Raft, no etcd. Just signed config files over SSH.
- No cross-host _runtime_ state (e.g. shared connection tracking) — out of scope, kernel-level concern.

---

## 5. Test kit — `zeerak-testkit`

A firewall is only as good as your confidence that it does what you think. `zeerak-testkit` ships in the same repo and is used by both contributors (CI) and operators (pre-prod validation).

### What it does

1. **Spin up an isolated environment** — Linux network namespaces by default (fast, root-only, runs in CI), or full QEMU/Firecracker microVMs for kernel-level realism.
2. **Apply a Zeerak config** to the test target.
3. **Run scenarios** — declarative YAML describing expected reachability:
   ```yaml
   # testkit/scenarios/caddy-box.yaml
   target: caddy-box
   apply: presets/caddy-box.yaml
   probes:
     - { from: home_ip, to: target:22, expect: allow }
     - { from: random, to: target:22, expect: drop }
     - { from: random, to: target:443, expect: allow }
     - { from: target, to: 1.1.1.1:53, expect: allow } # egress
   ```
4. **Report** — pass/fail per probe, generated nft diff, packet counters, captured pcap on failure.

### Components

- `testkit/harness/` — namespace + microVM lifecycle, IP/route plumbing.
- `testkit/probes/` — TCP/UDP/ICMP/HTTP probes; rate-limit & conntrack probes.
- `testkit/scenarios/` — bundled scenarios mirroring every preset Zeerak ships, plus regression cases (e.g. _"Docker bridge still works after default-deny"_).
- `testkit/cluster/` — multi-node scenarios for master/agent sync, partition, drift, rollback-on-disconnect.
- `zeerak testkit run [scenario]` — CLI entry point, also runnable as `go test ./testkit/...`.

### Fuzzing & property tests

- **Renderer round-trip**: random `model.Rule` → render → parse with `nft -j` → compare. Catches drift between our model and the kernel's view.
- **Config fuzzer**: feed malformed `zeerak.yaml` into the loader; must reject cleanly, never panic, never half-apply.
- **Rollback fuzzer**: random sequences of stage/commit/abort/timeout; running ruleset must always equal the last _confirmed_ config.

### CI integration

- Every PR runs the namespace-based test kit on GitHub Actions (no privileged hardware needed).
- Nightly job runs the microVM scenarios on a self-hosted runner (or [namespace.so](https://namespace.so)-style ephemeral VM).
- Releases are blocked on green test kit + signed reproducible build.

---

## 6. Other integrations (post-v1, planned)

- **Docker**: detect Docker's `DOCKER` and `DOCKER-USER` chains, surface them, let you add rules to `DOCKER-USER` safely.
- **Tailscale**: detect `tailscale0`, presets like _"admin services only on tailnet"_.
- **NATS**: detect a local `nats-server` (config or `:8222` monitoring endpoint), surface its client/route/leafnode/gateway/WebSocket ports (4222/6222/7422/7522/443), and one-click presets like _"NATS clients on tailnet only"_, _"cluster routes pinned to private CIDRs"_, or _"leafnode/gateway over WireGuard"_. Warn if the firewall blocks a port `nats-server` is listening on (same footgun pattern as Caddy).
- **fail2ban / CrowdSec**: visualize their bans, allow Zeerak to manage the underlying nft sets directly.
- **GeoIP / threat feeds**: scheduled-updated nft sets from MaxMind / Spamhaus / Firehol.

---

## 7. MCP support — `zeerak-mcp`

Zeerak ships a first-class **[Model Context Protocol](https://modelcontextprotocol.io)** server so AI assistants (Claude Desktop, Copilot, Continue, Cursor, custom agents) can read state and — _carefully_ — propose changes. Same safety bar as a human: every mutation goes through stage → preview → commit-with-rollback.

### Why bother?

- _"Why is my web app unreachable?"_ → the assistant inspects the running ruleset, journald drops, and Caddy bindings, then explains the gap.
- _"Allow Postgres only from the app subnet"_ → the assistant drafts a rule, the user sees the diff in the Zeerak UI, clicks confirm. **Humans always commit.**
- Onboarding: nftables has a steep learning curve. An assistant that can read a _real_ config and explain it lowers the bar a lot.

### Capabilities (read → propose → commit, never auto-apply)

**Resources** (read-only, safe to expose broadly):

- `zeerak://config` — current `zeerak.yaml`
- `zeerak://ruleset` — rendered nftables ruleset
- `zeerak://ruleset/live` — what the kernel is _actually_ running (drift indicator)
- `zeerak://chains/{family}/{table}/{chain}` — zoom into a chain
- `zeerak://sets/{name}` — named sets/maps
- `zeerak://logs?since=...` — recent journald drops, parsed
- `zeerak://presets` — catalog of available presets
- `zeerak://cluster/agents` — fleet status (cluster mode)

**Tools** (mutating tools are gated; see Safety):

- `explain_rule(rule)` — plain-English summary, no side effects
- `simulate_packet(src, dst, port, proto)` — trace verdict through current ruleset, no side effects
- `propose_change(patch)` — stage a change, return the diff + a `proposal_id`. Does **not** apply.
- `preview_proposal(proposal_id)` — dry-run rendered diff + plain-English summary
- `apply_preset(name, params)` — stages the preset; same flow as above
- `confirm_proposal(proposal_id)` — commits with the auto-rollback timer. **Disabled by default**; requires explicit opt-in per server config.
- `discard_proposal(proposal_id)`

### Safety model

MCP is a force multiplier _and_ a bigger blast radius. Defaults are conservative:

1. **Read-only by default.** A fresh `zeerak-mcp` install only exposes resources + non-mutating tools. The user must opt in to staging tools and _separately_ to the commit tool.
2. **Two channels for confirmation.** Even when `confirm_proposal` is enabled, the auto-rollback timer means a human still has to click "Keep changes" in the Zeerak UI within N seconds. The assistant cannot bypass this.
3. **Scoped tokens.** MCP clients connect with a token that carries a scope (`read`, `propose`, `commit`) and an optional allowlist of chains/tables they can touch.
4. **Full audit.** Every MCP call is logged to journald with the client identity, tool name, arguments, and resulting `proposal_id` — same trail as UI/CLI changes.
5. **Sandbox mode.** `zeerak-mcp --sandbox` runs against a copy of the ruleset in a netns (using the test kit) so an assistant can iterate freely without touching production.

### Transports & deployment

- **Local stdio** — default, for Claude Desktop / IDE plugins on the same host.
- **HTTP + SSE / streamable HTTP** — for remote assistants; lives behind the same reverse proxy as the UI, with the same auth (mTLS / `forward_auth`).
- Ships as `zeerak-mcp` (separate binary, same repo) and as a subcommand: `zeerak mcp serve`.
- Cluster-aware: pointed at a master, the MCP server can read fleet-wide resources and stage changes per-agent (commit still goes through master's normal flow).

### Example session

```
user:   "Why can't I reach my Jellyfin from the LAN?"
ai:     reads zeerak://ruleset/live, zeerak://logs?since=10m
        → "Your `inet filter input` chain drops on port 8096 because
           rule #4 only allows from 10.0.0.0/24, but the LAN is
           192.168.1.0/24. Want me to draft a fix?"
user:   "yes"
ai:     calls propose_change(...) → returns proposal_id=abc123
        opens the diff in the Zeerak UI
user:   reviews diff in UI, clicks "Apply (with 60s rollback)"
zeerak: applies, arms timer
user:   confirms reachable, clicks "Keep changes"
```

The assistant proposes; the human commits. Always.

---

## 8. Roadmap

**v0.1 + v0.2 — shipped.** Daemon, CLI, MCP read-only server, web panel with preset wizard, packaging (deb/rpm/apk/AUR/Homebrew/GHCR), netns test kit. See [README](README.md) for the user-facing feature list.

### v0.3 — Cluster & power features

- [ ] **Cluster mode v1**: master/agent over SSH (mTLS opt-in fallback), pull sync, fleet status view
- [ ] Cluster test-kit scenarios (partition, rollback-on-disconnect, drift)
- [ ] **MCP server v1** — staging tools (`propose_change`, `apply_preset`), opt-in commit, sandbox mode
- [x] Caddy admin-API panel _(read-only: detect + bound-ports cross-check; write flow deferred to v0.4)_
- [x] Docker chain awareness _(detection + dashboard pill; DOCKER-USER hand-off deferred)_
- [x] OpenAPI spec _(shipped at `/openapi.yaml`; generated client TBD)_
- [x] Named sets/maps editor (CIDR lists, country blocks)
- [x] Rate-limiting / connection-tracking rule helpers _(SSH `rate_limit.per_minute`)_
- [x] Tailscale + WireGuard awareness _(detect + SSH `interfaces:` pinning)_
- [x] OIDC / `forward_auth` _(Caddyfile.example + docs/auth.md)_

### Later

- [~] **NAT & port-forward** — DNAT/masquerade compile under `presets.port_forwards` / `presets.masquerade` into `ip zeerak-nat`; edit-form UI + hairpin/redirect presets pending (v0.5)
- [~] **Policy routing marks** — `presets.marks` compile into `inet zeerak-marks` (route hook); split-tunnel / QoS preset UI pending (v0.5)
- [~] **Conntrack helpers & zones** — `presets.ct_helpers` (ftp/sip/tftp/pptp/irc/h323) compile into `inet zeerak-ct`; zones + custom timeouts pending (v0.5)
- [ ] IPv6 parity audit (NAT table is currently IPv4-only by design; nft/ip6 NAT story TBD)
- [ ] Cluster: push sync, drift auto-heal, group templates
- [ ] microVM-based test kit on self-hosted CI
- [ ] Plugin system for custom presets

---

## 9. Design decisions

All v1 design questions are locked. Concise reference; rationale lives in
git history (`docs: lock all §11 design decisions`) and future ADRs under
`docs/decisions/`.

| #   | Question              | Decision                                                                                                                      |
| --- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 1   | Rule model            | Faithful nftables mirror; higher-level policy UI compiles down to user-owned tables (e.g. `inet zeerak-policy`).              |
| 2   | Auth                  | Zero built-in. Listen on `127.0.0.1` + unix socket; reverse proxy / SSH tunnel handles auth.                                  |
| 3   | UI vs file ownership  | Caddy-style: `/etc/zeerak/zeerak.yaml` is hand-edited (never rewritten), UI edits persist to `/var/lib/zeerak/autosave.yaml`. |
| 4   | Cluster transport     | SSH-first using operator's existing keys; mTLS opt-in fallback.                                                               |
| 5   | Cluster config format | Directory tree under `/etc/zeerak/cluster/` by default; `--cluster-git-url` for GitOps mode.                                  |
| 6   | Test kit backend      | netns in CI (every PR), microVMs nightly. Releases blocked on green for both.                                                 |
| 7   | MCP commit tool       | `confirm_proposal` disabled by default; humans commit. Auto-rollback timer is a second human checkpoint.                      |
| 8   | MCP transport         | stdio **and** HTTP+SSE shipped together from day one.                                                                         |
| 9   | Distro support        | Tier 1: Debian/Ubuntu, Fedora, Arch, Alpine (musl). Tier 2: openSUSE, NixOS, Homebrew (CLI only).                             |
| 10  | License               | Apache-2.0 + reserved "Zeerak" name (see `TRADEMARKS.md`).                                                                    |
| 11  | Telemetry             | None, ever, in core. Optional loopback-only Prometheus `/metrics`, opt-in.                                                    |

---

## 10. Inspirations & prior art

- **firewalld** — zone model is nice; XML config is not.
- **ufw** — simplicity goal; but CLI-only and iptables-era.
- **OPNsense / pfSense** — feature-rich; way too heavy for our target.
- **Mikrotik RouterOS "safe mode"** — auto-rollback UX we're cribbing.
- **Caddy** — DX north star: one binary, sensible defaults, great docs.
- **Tailscale admin panel** — clean, focused UI we admire.

---

## 11. How to contribute to _this document_

This file is the living design doc. PRs welcome. If you disagree with a design choice, open an issue with a "Decision proposal" — we'll discuss in the open and record the outcome in `docs/decisions/` (lightweight ADRs).
