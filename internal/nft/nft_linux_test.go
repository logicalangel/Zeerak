//go:build linux

package nft

import (
	"context"
	"os/exec"
	"testing"

	"github.com/zeerak/zeerak/internal/model"
)

// TestLinuxAdapter_RoundTrip exercises Apply -> Snapshot against a real
// `nft` binary and an empty network namespace. Skips when:
//   - nft is not on PATH (dev container without nftables)
//   - we lack CAP_NET_ADMIN (run under `unshare -U -r -n` in CI)
//
// The CI workflow invokes this via `unshare -U -r -n go test ./...`.
func TestLinuxAdapter_RoundTrip(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not on PATH")
	}
	// Cheap permission probe: `nft list ruleset` requires CAP_NET_ADMIN.
	if err := exec.Command("nft", "list", "ruleset").Run(); err != nil {
		t.Skipf("nft list ruleset failed (need CAP_NET_ADMIN; try `unshare -U -r -n`): %v", err)
	}

	a := newPlatform()
	rs := &model.Ruleset{Tables: []model.Table{{
		Family: model.FamilyINet,
		Name:   "zeerak-test",
		Owned:  true,
		Chains: []model.Chain{{
			Name:     "input",
			Type:     model.ChainTypeFilter,
			Hook:     model.HookInput,
			Priority: 0,
			Policy:   model.VerdictAccept,
			Rules: []model.Rule{
				{Expr: "tcp dport 22 accept", Comment: "ssh"},
			},
		}},
	}}}

	if err := a.Apply(context.Background(), rs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", "zeerak-test").Run()
	})

	snap, err := a.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap.Tables) != 1 || snap.Tables[0].Name != "zeerak-test" {
		t.Fatalf("snapshot did not echo applied table: %+v", snap)
	}
}
