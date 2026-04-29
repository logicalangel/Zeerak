# Zeerak test kit — `zeerak-testkit`

Lightweight test harness for Zeerak. Used by CI on every PR and by operators
for pre-prod validation. Two backends:

| Backend  | Speed   | Realism                | Used in              |
| -------- | ------- | ---------------------- | -------------------- |
| netns    | fast    | shared kernel          | every PR (CI)        |
| microVM  | slow    | dedicated kernel       | nightly (self-hosted)|

See [VISION.md §7](../VISION.md) and [§11 Q6](../VISION.md#11-open-questions).

## Layout

```
testkit/
├── harness/
│   ├── netns/        # `ip netns` wrapper (this directory)
│   └── microvm/      # QEMU/Firecracker wrapper (v0.1)
├── probes/           # TCP/UDP/ICMP/HTTP probes (v0.1)
└── scenarios/        # YAML scenarios mirroring presets (v0.1)
```

## Why shell out to `ip` / `nft` / `iproute2`?

Per VISION.md design principle 3 ("Use the OS"), the test kit deliberately
drives the standard Linux network tools (`ip netns`, `ip link`, `nft`, `ss`,
`iperf3`) rather than reimplementing them in Go. They're already audited,
already on every target distro, and their CLI is the Linux-documented
interface. The harness is a thin Go layer that orchestrates them and parses
output.

## Running locally

The netns backend needs `CAP_NET_ADMIN`:

```sh
sudo go test ./testkit/...
# or, in CI / a sandbox:
unshare -U -r -n go test ./testkit/...
```

The microVM backend needs `kvm` access; nightly only.
