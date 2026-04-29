// Package nft is Zeerak's nftables adapter — the kernel-facing implementation
// of stager.Applier.
//
// Per VISION.md §11 Q1 (rule model) and design principle 3 ("use the OS"):
//
//   - v0.1 shells out to the standard `nft` binary for both reads and
//     writes. `nft -f -` is atomic at the netlink level, which is exactly
//     the apply semantics Zeerak needs.
//   - v0.2+ adds a google/nftables (netlink) fast path under the same
//     interface for shaving startup latency and avoiding the nft fork cost.
//
// Zeerak only ever modifies tables marked Owned=true (typically
// `inet zeerak-policy`). Unowned tables — Docker's `ip nat`, fail2ban's
// sets, anything the operator hand-wrote — are read-only to this adapter.
// The renderer already filters by Owned; this package enforces the same
// invariant on the apply path.
package nft

import (
	"context"

	"github.com/zeerak/zeerak/internal/model"
)

// Adapter is the contract this package satisfies. Snapshot+Apply match
// stager.Applier exactly so the stager can hold an *Adapter (Linux) or
// a fake (tests). LiveText/LiveTable feed the read-only UI and the
// /preview diff endpoint.
type Adapter interface {
	Snapshot(ctx context.Context) (*model.Ruleset, error)
	Apply(ctx context.Context, rs *model.Ruleset) error
	// LiveText returns the entire kernel ruleset as `nft list ruleset` text.
	LiveText(ctx context.Context) (string, error)
	// LiveTable returns `nft list table FAMILY NAME` text. A missing table
	// returns ("", nil) so callers can diff against an empty string.
	LiveTable(ctx context.Context, family model.Family, name string) (string, error)
}

// New returns the platform Adapter. On Linux this drives `nft`; on other
// platforms it returns a stub that errors on every call (so the daemon
// still builds for dev on macOS).
func New() Adapter { return newPlatform() }
