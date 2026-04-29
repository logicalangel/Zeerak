# Zeerak

> A lightweight, friendly **web GUI firewall for nftables**.
> Single binary. Safe by default. Plays nicely with Caddy.

🚧 **Status:** early design phase — see [VISION.md](VISION.md) for the full plan.

## What it is

Zeerak is a small Go daemon that gives you a clean web UI to manage your Linux host's `nftables` firewall — without the foot-guns. Stage rule changes, preview the diff, commit with an auto-rollback timer so you can never lock yourself out.

## What it isn't

A full router OS. Use OPNsense/pfSense for that. Zeerak is for the single-VPS / homelab-host / small-team-server case.

## Quick links

- 📜 [VISION.md](VISION.md) — design doc, roadmap, open questions
- 💬 Discussions — _(coming soon)_

## Stack

Go · HTMX · Svelte islands · Tailwind · shadcn-svelte · nftables (netlink, via [`google/nftables`](https://github.com/google/nftables))

No database. The running config is a single YAML file (hand-edit `/etc/zeerak/zeerak.yaml`, or let the UI manage `/var/lib/zeerak/autosave.yaml`) — Caddy-style. Audit lives in `journald`, history lives in `git`.

## License

[Apache-2.0](LICENSE). The **"Zeerak" name and logo are reserved** to the upstream project — see [TRADEMARKS.md](TRADEMARKS.md). Forks welcome; pick your own name.
