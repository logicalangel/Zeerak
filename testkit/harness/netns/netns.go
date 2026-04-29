// Package netns provides a thin wrapper around the Linux `ip netns` and
// related commands for the Zeerak test kit.
//
// Per VISION.md §11 Q6 (test kit default backend):
//
//	"Network namespaces in CI (every PR — fast, rootless-friendly,
//	 no privileged hardware), microVMs nightly."
//
// We deliberately shell out to the standard iproute2 / nft tools rather than
// reimplementing them in Go. They are already on every target distro, well-
// audited, and their CLI is the documented Linux interface for this stuff.
//
// This file is a stub: real probes/scenarios land in v0.1.
package netns

import (
	"context"
	"fmt"
	"os/exec"
)

// Harness manages a set of named Linux network namespaces for one test run.
type Harness struct {
	Prefix string // e.g. "zk-test"; namespaces are <prefix>-<name>.
	created []string
}

// New returns a Harness; call Close to delete every namespace it created.
func New(prefix string) *Harness {
	if prefix == "" {
		prefix = "zk-test"
	}
	return &Harness{Prefix: prefix}
}

// Add creates a netns named <prefix>-<name> via `ip netns add`.
// Requires CAP_NET_ADMIN (root, or `unshare --net` in CI).
func (h *Harness) Add(ctx context.Context, name string) error {
	full := h.full(name)
	if err := run(ctx, "ip", "netns", "add", full); err != nil {
		return fmt.Errorf("netns add %s: %w", full, err)
	}
	h.created = append(h.created, full)
	return nil
}

// Exec runs argv inside the named netns via `ip netns exec`.
func (h *Harness) Exec(ctx context.Context, name string, argv ...string) ([]byte, error) {
	full := h.full(name)
	cmd := append([]string{"netns", "exec", full}, argv...)
	out, err := exec.CommandContext(ctx, "ip", cmd...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ip %v: %w (%s)", cmd, err, out)
	}
	return out, nil
}

// Close deletes every namespace this harness created. Best-effort; logs but
// does not fail on individual deletes (CI runner gets reaped anyway).
func (h *Harness) Close(ctx context.Context) {
	for _, ns := range h.created {
		_ = run(ctx, "ip", "netns", "del", ns)
	}
	h.created = nil
}

func (h *Harness) full(name string) string { return h.Prefix + "-" + name }

func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, out)
	}
	return nil
}
