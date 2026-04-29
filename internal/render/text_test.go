package render

import (
	"strings"
	"testing"

	"github.com/zeerak/zeerak/internal/model"
)

// TestText_CaddyBox renders a minimal "Caddy box" preset and checks the
// output contains the expected nft snippets. Acts as a smoke test for the
// text renderer until the round-trip fuzz harness lands (see testkit/).
func TestText_CaddyBox(t *testing.T) {
	rs := &model.Ruleset{
		Tables: []model.Table{
			{
				Family: model.FamilyINet,
				Name:   "zeerak-policy",
				Owned:  true,
				Chains: []model.Chain{
					{
						Name:     "input",
						Type:     model.ChainTypeFilter,
						Hook:     model.HookInput,
						Priority: 0,
						Policy:   model.VerdictDrop,
						Rules: []model.Rule{
							{Expr: "ct state established,related accept", Comment: "conntrack"},
							{Expr: "iifname lo accept", Comment: "loopback"},
							{Expr: "tcp dport 22 accept", Comment: "ssh"},
							{Expr: "tcp dport { 80, 443 } accept", Comment: "caddy"},
						},
					},
				},
			},
		},
	}
	out, err := String(rs, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"table inet zeerak-policy {",
		"chain input {",
		"type filter hook input priority 0; policy drop;",
		`tcp dport 22 accept comment "ssh"`,
		`tcp dport { 80, 443 } accept comment "caddy"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestText_OwnedFilter verifies unowned tables are skipped by default.
func TestText_OwnedFilter(t *testing.T) {
	rs := &model.Ruleset{
		Tables: []model.Table{
			{Family: model.FamilyIP, Name: "nat", Owned: false},
			{Family: model.FamilyINet, Name: "zeerak-policy", Owned: true},
		},
	}
	out, err := String(rs, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "table ip nat") {
		t.Error("unowned table leaked into default render")
	}
	if !strings.Contains(out, "table inet zeerak-policy") {
		t.Error("owned table missing from default render")
	}

	all, _ := String(rs, true)
	if !strings.Contains(all, "table ip nat") {
		t.Error("includeUnowned=true should emit unowned tables")
	}
}
