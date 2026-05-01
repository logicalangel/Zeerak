// Package wireguard provides best-effort WireGuard awareness for Zeerak.
//
// VISION.md §8 lists "WireGuard host interfaces" as a v0.3 awareness item.
// Like the tailscale package, this is read-only detection via /sys/class/net.
// We do NOT shell out to `wg show` (requires root or CAP_NET_ADMIN).
package wireguard

import (
	"os"
	"sort"
	"strings"
)

// Result describes which WireGuard interfaces are present.
type Result struct {
	Detected   bool
	Interfaces []string // e.g. ["wg0", "wg-corp"]
}

// Detect scans /sys/class/net for WireGuard-style interfaces.
//
// Naming is by convention (wg0, wg-name, ...); we match anything starting
// with "wg" and either followed by a digit or a hyphen, to avoid collecting
// e.g. "wgbridge" if someone names a non-WG interface that way. False
// positives here are harmless (we only display them as awareness, never
// auto-firewall) but the convention check keeps the noise down.
func Detect() Result {
	return scanSysNet("/sys/class/net")
}

func scanSysNet(dir string) Result {
	out := Result{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "wg") {
			continue
		}
		if name == "wg" {
			continue
		}
		c := name[2]
		if !(c == '-' || c == '_' || (c >= '0' && c <= '9')) {
			continue
		}
		out.Interfaces = append(out.Interfaces, name)
	}
	sort.Strings(out.Interfaces)
	out.Detected = len(out.Interfaces) > 0
	return out
}
