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
- 💬 Discussions — *(coming soon)*

## Stack

Go · HTMX · Svelte islands · Tailwind · SQLite · nftables (netlink)

## License

TBD — see [VISION.md §8](VISION.md#8-open-questions-lets-discuss).
