// Package tailscale provides best-effort Tailscale awareness for Zeerak.
//
// VISION.md §8 promises: "detect tailscale0, presets like 'admin services
// only on tailnet'." This package implements the detection half. The preset
// half lives in internal/policy.SSHPreset.Interfaces.
//
// Detection is intentionally cheap and read-only: we list /sys/class/net
// looking for a Tailscale-style interface. We never run `tailscale status`
// or hit the local API — that requires root or membership in the tailscale
// group, which is more privilege than awareness needs.
package tailscale

import (
	"os"
	"strings"
)

// Result describes what we found on the host.
type Result struct {
	// Detected is true when at least one Tailscale interface is present.
	Detected bool
	// Interfaces is the list of detected interface names (typically
	// "tailscale0", "userspace-networking" mode may produce others).
	Interfaces []string
}

// Detect inspects /sys/class/net and returns the Tailscale interfaces.
// Always returns a non-nil Result; on systems without /sys (macOS dev box)
// it returns Detected=false with no error.
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
		// Common patterns: tailscale0, tailscale1; userspace-networking
		// usually exposes the tunnel as a TUN device named "tailscale".
		if name == "tailscale" || strings.HasPrefix(name, "tailscale") {
			out.Detected = true
			out.Interfaces = append(out.Interfaces, name)
		}
	}
	return out
}
