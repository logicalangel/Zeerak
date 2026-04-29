# Zeerak — A Lightweight Web GUI Firewall for nftables

> **Zeerak** (زیرک) — _clever, sharp, perceptive_ in Persian.
> A small, friendly firewall manager that doesn't get in your way.

---

## 1. Why Zeerak?

Most Linux firewall front-ends fall into two camps:

- **Heavyweight** (pfSense/OPNsense-style appliances) — full OSes, overkill for a single VPS or homelab box.
- **Bare** (`nft`, `iptables`, `ufw`) — powerful but unfriendly; easy to lock yourself out, hard to reason about rule order.

Zeerak aims for the **sweet spot**: a single small binary you drop on a Linux host that gives you a clean web UI to manage **nftables** rules safely, with sensible defaults, presets for common use cases, and tight integration with tools you already use (Caddy, Docker, Tailscale, fail2ban).

### Design principles

1. **Lightweight** — single static Go binary, < 15 MB, no runtime deps beyond `nft`.
2. **No database, no user system** — like Caddy. A single config file (`zeerak.yaml`) is the source of truth. Auth is offloaded to a reverse proxy or a unix socket.
3. **Use the OS** — audit lives in `journald`, history lives in `git`, secrets live in the filesystem. Don't reinvent what Linux already does well.
4. **Safe by default** — every rule change goes through _staged → preview (diff) → commit with auto-rollback timer_. You can't lock yourself out.
5. **Readable** — the UI shows nftables in human terms _and_ shows the generated `nft` ruleset side-by-side. Power users keep their power.
6. **Opinionated presets** — "allow SSH from my IP", "expose Caddy on 80/443", "block country X", "only Tailscale" — one click.
7. **Great DX** — clear API, OpenAPI spec, declarative config (so it can live in git), `zeerak` CLI mirrors the UI.
8. **Boring tech** — Go + server-rendered HTML (HTMX) + a sprinkle of Svelte for interactivity. No SPA build hell.
9. **Open source, easy to install** — 100% open-source on GitHub, developed in the open. Distributed through standard public channels: GitHub Releases, Docker Hub / GHCR, and major distro repositories (Debian/Ubuntu APT, Fedora COPR, Arch AUR, Alpine, Homebrew). A single `apt install zeerak` / `dnf install zeerak` / `brew install zeerak` should _just work_ — no curl-pipe-bash required.

### Open source

Zeerak is **open source from day one** under **Apache-2.0**, developed in public on GitHub. Issues, design discussions, and roadmap live in the repo. The Apache-2.0 license is OSI-approved, free forever for personal and commercial use — but the **"Zeerak" name and logo are reserved** to the upstream project (see `TRADEMARKS.md`). Forks are welcome; they just need to pick their own name.

### Distribution — install from public repositories

The goal is that any Linux user can get Zeerak with a single command from the package manager they already trust:

| Channel          | Command                                                                  |
| ---------------- | ------------------------------------------------------------------------ |
| Debian / Ubuntu  | `apt install zeerak` (official PPA, then upstream Debian)                |
| Fedora / RHEL    | `dnf install zeerak` (Fedora COPR, then official)                        |
| Arch Linux       | `pacman -S zeerak` (AUR first, then community)                           |
| Alpine           | `apk add zeerak`                                                         |
| openSUSE         | `zypper install zeerak` (OBS)                                            |
| macOS (CLI only) | `brew install zeerak`                                                    |
| Containers       | `docker pull ghcr.io/zeerak/zeerak`                                      |
| Source           | `go install github.com/zeerak/zeerak/cmd/zeerak-server@latest`           |
| Manual           | static binaries on every GitHub Release (signed with cosign + checksums) |

Releases are reproducible, signed, and accompanied by an SBOM. No proprietary build steps, no closed binaries.

### Non-goals (for v1)

- Not a full router OS — no DHCP, DNS, VPN _server_, or captive portal. (NAT/forwarding rules **are** in scope; nftables does that natively and we'll surface it.)
- Not a heavyweight fleet orchestrator — cluster mode (§6) is intentionally simple master/agent config distribution, not a SaaS control plane.
- Not iptables-compatible — nftables only.

---

## 2. Target Users & Use Cases

| Persona              | Use case                                                                      |
| -------------------- | ----------------------------------------------------------------------------- |
| Solo dev with a VPS  | Expose Caddy on 80/443, SSH only from home IP, drop everything else.          |
| Homelab tinkerer     | Segment LAN/IoT/guest, block outbound from IoT, allow Jellyfin from LAN only. |
| Small team / startup | GitOps-friendly firewall config on app servers, no surprise lockouts.         |
| Learner              | See the UI choice → see the generated `nft` rule. Learn nftables by doing.    |

### Concrete v1 scenarios

- **"Caddy box"**: allow 22 (from my IP), 80, 443; drop everything else; log drops.
- **"Docker host"**: integrate cleanly with Docker's nftables chains without fighting them.
- **"Wireguard/Tailscale-only admin"**: SSH only reachable over the tunnel.
- **"Country block"**: drop traffic from a list of CIDRs (ipset-backed, auto-updated).
- **"Rate-limit SSH"**: 5 attempts/min/IP, drop excess.

---

## 3. Architecture (proposed)

```
┌──────────────────────────────────────────────┐
│  Browser (HTMX + Svelte islands + Tailwind)  │
└──────────────────┬───────────────────────────┘
                   │ HTTPS + auth (handled by reverse proxy)
┌──────────────────▼───────────────────────────┐
│  Caddy / nginx / Tailscale Serve             │
│  - TLS, optional forward_auth / SSO          │
└──────────────────┬───────────────────────────┘
                   │ HTTP on 127.0.0.1 or unix socket
┌──────────────────▼───────────────────────────┐
│  zeerak-server (single Go binary)            │
│  ├── HTTP API (chi) + HTMX views             │
│  ├── Config loader/watcher (zeerak.yaml)     │
│  ├── Rule engine                             │
│  │     model → validator → nft renderer      │
│  ├── Stager (apply with auto-rollback)       │
│  └── Integrations: Caddy, Docker, Tailscale  │
└─────┬─────────────────────────────┬──────────┘
      │ netlink / `nft -j`           │ structured logs
┌─────▼──────────────┐         ┌─────▼──────────┐
│  kernel: nftables  │         │  systemd-      │
│                    │         │  journald      │
└────────────────────┘         └────────────────┘
```

### Stack

- **Language**: Go — single static binary, great for sysadmin tooling.
- **Web**: server-rendered HTML + [HTMX](https://htmx.org) for interactivity, small Svelte islands for the rule editor / live diff.
- **UI components**: [**shadcn-svelte**](https://www.shadcn-svelte.com) — copy-in components (not a dep), accessible, themeable, and matches the "boring tech, great DX" line. We own the component code, no surprise upstream churn.
- **Styling**: Tailwind CSS (which shadcn-svelte builds on).
- **State**: **none on disk except `zeerak.yaml`**. The config file is the source of truth — like `Caddyfile` or `caddy.json`. Reload on SIGHUP / API call. Put it in `/etc/zeerak/zeerak.yaml`, version it with `git`.
- **No user database**: Zeerak listens on `127.0.0.1` or a unix socket by default. Auth (TLS, SSO, basic auth, IP allowlist) is the reverse proxy's job — exactly the pattern Caddy itself uses for its admin API on `:2019`.
- **No audit table**: every config change is logged to `journald` (who/what/when from the proxy + the diff), and history is whatever `git log /etc/zeerak/` tells you. `journalctl -u zeerak` is your audit trail.
- **nftables interface**: prefer [`google/nftables`](https://github.com/google/nftables) (netlink) for reads & atomic transactions; shell out to `nft -f -` as a fallback for human-readable apply.
- **API**: REST + OpenAPI 3.1 spec generated from code.
- **CLI**: `zeerak` binary speaks the same API over the unix socket — handy for scripts & GitOps.

### Repo layout (initial sketch)

```
zeerak/
├── cmd/
│   ├── zeerak-server/      # daemon
│   └── zeerak/             # CLI
├── internal/
│   ├── config/             # zeerak.yaml loader, watcher, validator
│   ├── model/              # Rule, Chain, Set, Policy types
│   ├── render/             # model → nft ruleset
│   ├── nft/                # netlink + `nft` shell adapter
│   ├── stager/             # stage → preview → commit → rollback
│   ├── api/                # HTTP handlers + OpenAPI (loopback / unix sock)
│   ├── cluster/            # master/agent sync over SSH (mTLS fallback), push/pull
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
├── testkit/                # zeerak-testkit: VM/netns harness + scenarios
├── docs/
└── VISION.md               # this file
```

---

## 4. Safety: the "auto-rollback" pattern

The single biggest fear with a remote firewall UI is **locking yourself out**. Zeerak's apply flow:

1. **Stage** changes — edited in DB, not applied.
2. **Preview** — UI shows a unified diff of the rendered `nft` ruleset, plus a plain-English summary ("This will block port 22 from 0.0.0.0/0").
3. **Commit with armed rollback** — apply the new ruleset _and_ schedule a revert in **N seconds** (default 60).
4. **Confirm** — user must click "Keep changes" from the (still-reachable) browser within the window, or Zeerak rolls back automatically.

This is borrowed from Mikrotik's "safe mode" and from `iptables-apply`. It should be the default for _every_ destructive change.

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
  - One-click create matching firewall rules: _"Caddy listens on 80/443 → ensure inbound 80/443 are allowed"_.
  - Warn if firewall blocks a port Caddy is bound to (very common footgun).
- Optional: edit Caddyfile through Zeerak with the same stage→preview→commit flow.

Both modes are **opt-in** and decoupled: you can use A without B.

> 💡 We are also borrowing Caddy's _operational_ model, not just integrating with it: **no DB, no user table, config file = source of truth, OS handles auth + logging**.

---

## 6. Cluster mode — master/agent config distribution

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

## 7. Test kit — `zeerak-testkit`

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

## 8. Other integrations (post-v1, planned)

- **Docker**: detect Docker's `DOCKER` and `DOCKER-USER` chains, surface them, let you add rules to `DOCKER-USER` safely.
- **Tailscale**: detect `tailscale0`, presets like _"admin services only on tailnet"_.
- **fail2ban / CrowdSec**: visualize their bans, allow Zeerak to manage the underlying nft sets directly.
- **GeoIP / threat feeds**: scheduled-updated nft sets from MaxMind / Spamhaus / Firehol.

---

## 9. MCP support — `zeerak-mcp`

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

## 10. Roadmap

### v0.1 — "It works on my VPS"

- [ ] `zeerak.yaml` schema + loader + validator
- [ ] Read current nftables ruleset, render in UI (read-only)
- [ ] Rule model + renderer + round-trip tests
- [ ] Listen on loopback + unix socket; example Caddyfile with `forward_auth`
- [ ] Stage → preview (diff) → commit-with-rollback
- [ ] Presets: "Caddy box", "SSH from my IP", "default deny inbound"
- [ ] Structured logs to journald
- [ ] Caddyfile example + systemd unit
- [ ] **Test kit v0**: netns harness + scenarios for every shipped preset, wired into CI

### v0.2 — Integrations

- [ ] Caddy admin-API panel (read-only first, then write)
- [ ] Docker chain awareness
- [ ] CLI (`zeerak apply -f config.yaml`) — GitOps-friendly
- [ ] OpenAPI spec + generated client
- [ ] Public packages: `.deb` PPA, Fedora COPR, AUR, Homebrew tap, GHCR image
- [ ] **MCP server v0** — read-only resources + `explain_rule` / `simulate_packet`, both stdio **and** HTTP+SSE transports

### v0.3 — Cluster & power features

- [ ] **Cluster mode v1**: master/agent over SSH (mTLS opt-in fallback), pull sync, fleet status view
- [ ] Cluster test-kit scenarios (partition, rollback-on-disconnect, drift)
- [ ] **MCP server v1** — staging tools (`propose_change`, `apply_preset`), opt-in commit, sandbox mode
- [ ] Named sets/maps editor (CIDR lists, country blocks)
- [ ] Rate-limiting / connection-tracking rule helpers
- [ ] Tailscale + WireGuard awareness
- [ ] OIDC / `forward_auth`

### Later

- [ ] IPv6 parity audit
- [ ] Cluster: push sync, drift auto-heal, group templates
- [ ] microVM-based test kit on self-hosted CI
- [ ] Plugin system for custom presets

---

## 11. Open questions

1. **Rule model**: ✅ _Decided — two-layer, nftables-native._ Zeerak's internal model is a **thin, faithful mirror of nftables** (families, tables, chains, hooks, priorities, sets/maps, verdicts, expressions) — no proprietary abstraction underneath. We render via [`google/nftables`](https://github.com/google/nftables) (netlink, atomic transactions) with `nft -f -` as fallback, and round-trip-fuzz against `nft -j` so the model never drifts from the kernel. On top of that we ship a **higher-level "policy" UI** (zones, services, presets like _"Caddy box"_, _"SSH from my IP"_) that compiles _down_ to plain nftables objects in user-owned tables (e.g. `inet zeerak-policy`) — no shadow chains, no hidden state. Every policy view has a "show me the `nft` it generates" toggle, and a per-chain **raw `nft` escape hatch** lets power users hand-write rules that sit alongside policy-generated ones. Rationale: matches how `firewalld`'s zone model maps to nftables, keeps the kernel's primitives (the Linux default) authoritative, and means `nft list ruleset` always tells the truth.
2. **Auth offload — how far?** ✅ _Decided._ Listen on `127.0.0.1` + unix socket, **zero auth in Zeerak itself** — no built-in fallback, no first-run token. Auth is _always_ the reverse proxy's / transport's job. Ship recipes for Caddy `basic_auth` / `forward_auth` (Authelia/Authentik/Pocket-ID), Tailscale Serve, and SSH tunnel; that's the whole story. Keeps the binary tiny and matches Caddy's admin-API model exactly.
3. **UI vs file ownership** of `zeerak.yaml`: ✅ _Decided — Caddy-style._ The running config is owned by Zeerak; the UI/API is authoritative and persists to an **autosave file** (`/var/lib/zeerak/autosave.yaml`, mirroring Caddy's `~/.config/caddy/autosave.json`). Users who prefer file-first workflows hand-edit `/etc/zeerak/zeerak.yaml` and `zeerak reload` (or SIGHUP) — exactly the Caddyfile vs admin-API split. No comment-preserving round-trip required: hand-authored files are _loaded_, never _rewritten_ by the UI; UI edits live in the autosave. `zeerak config export` dumps the current running config as clean YAML for git.
4. **Cluster transport**: ✅ _Decided — SSH-first._ Master reaches agents over **SSH using the operator's existing keys** (`~/.ssh/id_*` / agent forwarding / `~/.ssh/config` host aliases). No new PKI to manage, no cert rotation, works through any jump host / bastion the operator already uses, and benefits from years of hardened OpenSSH defaults. The "agent" is just `zeerak-server --agent` invoked over SSH (à la `ansible`'s transport). mTLS remains an _optional_ fallback for environments where SSH isn't available (e.g. minimal containers), but is **not** the default.
5. **Cluster config format**: ✅ _Decided — both, directory first._ Default is a plain directory tree under `/etc/zeerak/cluster/` (`defaults.yaml`, `groups/*.yaml`, `<host>.yaml`) — no extra deps, just files the operator already knows how to back up with `tar` / `rsync` / `git`. For fleet-as-code workflows, `zeerak-server --cluster-git-url <repo>` clones/pulls a git repo into that same tree on a watch interval; the rest of the pipeline (render → SSH → stage → rollback) is identical. Keeps the Linux-default toolchain (filesystem + `git`) authoritative and avoids inventing a config-distribution protocol on top of git.
6. **Test kit default backend**: ✅ _Decided._ **Network namespaces in CI** (every PR — fast, rootless-friendly, no privileged hardware), **microVMs nightly** (QEMU/Firecracker on a self-hosted runner — real kernel, catches namespace-incompatible behaviour like conntrack edge cases and `nft` netlink quirks). Releases are blocked on green for both.
7. **MCP commit tool default**: ✅ _Decided — humans commit, always._ `confirm_proposal` is **disabled out-of-the-box**. The MCP server can read state, explain rules, simulate packets, and stage proposals (`propose_change`, `apply_preset`) — but the _commit_ step is a human action in the Zeerak UI / CLI, period. Even if an operator opts in to `confirm_proposal` later, the auto-rollback timer still requires a human to click "Keep changes" within N seconds, so there are always **two human checkpoints** between an AI-drafted change and a permanent rule. No exceptions, no `--yolo` flag.
8. **MCP transport**: ✅ _Decided — both day one._ Ship **stdio _and_ HTTP+SSE / streamable HTTP** from v0. Stdio for local IDE/desktop assistants (Claude Desktop, Continue, Cursor on the same host); HTTP+SSE for remote agents, mounted behind the same reverse proxy as the UI with the same auth (`forward_auth` / mTLS). Same handler code, two listeners — the cost of adding HTTP next to stdio is small and remote-agent use cases (cluster-wide reasoning, ChatOps) are too valuable to defer.
9. **Distro support**: ✅ _Decided._ **Tier 1** at v0.2 packaging milestone: Debian/Ubuntu (PPA), Fedora (COPR), Arch (AUR), plus **Alpine (musl) for containers** — covers ~95% of homelab + VPS users. **Tier 2** (community/best-effort): openSUSE (OBS), NixOS, Homebrew (CLI only on macOS). Static `amd64` + `arm64` binaries on every GitHub Release, signed with cosign. Anything else is `go install` from source.
10. **License**: ✅ _Decided — Apache-2.0 + reserved "Zeerak" name._ Apache-2.0 maximizes adoption (homelabs, distros, enterprise), explicitly **does not grant trademark rights** (§6 of the license), and requires attribution via the `NOTICE` file — so derivative work is welcome but the **"Zeerak" name and logo are reserved** to the upstream project. A short `TRADEMARKS.md` will spell out the policy: forks must rename (e.g. `my-fork-of-zeerak`) and keep a visible "Based on Zeerak — https://github.com/zeerak/zeerak" attribution in their README and `--version` output. This gives us the upside of permissive licensing without losing the brand to a hostile fork — the same pattern Caddy, Terraform-pre-BSL, and Kubernetes use.
11. **Telemetry**: ✅ _Decided — none, ever (in core)._ Zeerak ships **zero phone-home, zero anonymous metrics, zero update pings**. A firewall is the worst possible product to bolt telemetry onto — by definition it sits on the network egress path of security-conscious users. Operators who want metrics can scrape the local `/metrics` Prometheus endpoint (opt-in, off by default, loopback only) — that's the only data plane Zeerak exposes, and it never leaves the host unless the operator wires it up themselves.

---

## 12. Inspirations & prior art

- **firewalld** — zone model is nice; XML config is not.
- **ufw** — simplicity goal; but CLI-only and iptables-era.
- **OPNsense / pfSense** — feature-rich; way too heavy for our target.
- **Mikrotik RouterOS "safe mode"** — auto-rollback UX we're cribbing.
- **Caddy** — DX north star: one binary, sensible defaults, great docs.
- **Tailscale admin panel** — clean, focused UI we admire.

---

## 13. How to contribute to _this document_

This file is the living design doc. PRs welcome. If you disagree with a design choice, open an issue with a "Decision proposal" — we'll discuss in the open and record the outcome in `docs/decisions/` (lightweight ADRs).
