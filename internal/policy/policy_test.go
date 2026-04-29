package policy

import (
	"strings"
	"testing"

	"github.com/zeerak/zeerak/internal/model"
)

func TestEmpty(t *testing.T) {
	if !(Presets{}).Empty() {
		t.Fatal("zero Presets should be Empty()")
	}
	if (Presets{CaddyBox: true}).Empty() {
		t.Fatal("CaddyBox should not be Empty()")
	}
}

func TestCompile_NilWhenEmpty(t *testing.T) {
	if got := (Presets{}).Compile(); got != nil {
		t.Fatalf("empty presets compiled to %v, want nil", got)
	}
}

func TestCompile_DefaultDenyInbound(t *testing.T) {
	tbl := Presets{DefaultDenyInbound: true}.Compile()
	if tbl == nil {
		t.Fatal("nil table")
	}
	if tbl.Family != model.FamilyINet || tbl.Name != TableName || !tbl.Owned {
		t.Fatalf("table header: %+v", *tbl)
	}
	if len(tbl.Chains) != 1 {
		t.Fatalf("chains: %d", len(tbl.Chains))
	}
	c := tbl.Chains[0]
	if c.Policy != model.VerdictDrop {
		t.Fatalf("policy=%q, want drop", c.Policy)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("rules: %d, want 2 (ct + lo)", len(c.Rules))
	}
	if !strings.Contains(c.Rules[0].Expr, "ct state established") {
		t.Fatalf("rule[0]: %q", c.Rules[0].Expr)
	}
	if !strings.Contains(c.Rules[1].Expr, "iifname lo") {
		t.Fatalf("rule[1]: %q", c.Rules[1].Expr)
	}
}

func TestCompile_PolicyAcceptWhenNoDeny(t *testing.T) {
	tbl := Presets{CaddyBox: true}.Compile()
	if tbl.Chains[0].Policy != model.VerdictAccept {
		t.Fatalf("policy=%q, want accept (no default_deny)", tbl.Chains[0].Policy)
	}
}

func TestCompile_SSHDefault(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{}}.Compile()
	c := tbl.Chains[0]
	if len(c.Rules) != 1 || !strings.Contains(c.Rules[0].Expr, "tcp dport 22 accept") {
		t.Fatalf("rules: %+v", c.Rules)
	}
}

func TestCompile_SSHCustomPort(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{Port: 2222}}.Compile()
	if !strings.Contains(tbl.Chains[0].Rules[0].Expr, "tcp dport 2222") {
		t.Fatalf("expr: %q", tbl.Chains[0].Rules[0].Expr)
	}
}

func TestCompile_SSHAllowlistSplitsByFamily(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{
		From: []string{"2001:db8::/32", "10.0.0.0/8", "192.168.1.0/24"},
	}}.Compile()
	rules := tbl.Chains[0].Rules
	if len(rules) != 2 {
		t.Fatalf("rules: %d, want 2 (v4 + v6)", len(rules))
	}
	// Determinism: v4 first (sorted), v6 second.
	if !strings.HasPrefix(rules[0].Expr, "ip saddr {") {
		t.Fatalf("v4 rule: %q", rules[0].Expr)
	}
	if !strings.Contains(rules[0].Expr, "10.0.0.0/8") || !strings.Contains(rules[0].Expr, "192.168.1.0/24") {
		t.Fatalf("v4 cidrs: %q", rules[0].Expr)
	}
	if !strings.HasPrefix(rules[1].Expr, "ip6 saddr {") {
		t.Fatalf("v6 rule: %q", rules[1].Expr)
	}
	if !strings.Contains(rules[1].Expr, "2001:db8::/32") {
		t.Fatalf("v6 cidrs: %q", rules[1].Expr)
	}
}

func TestCompile_OrderIsStable(t *testing.T) {
	// default_deny first, ssh next, caddy_box last.
	tbl := Presets{
		DefaultDenyInbound: true,
		SSH:                &SSHPreset{},
		CaddyBox:           true,
	}.Compile()
	rules := tbl.Chains[0].Rules
	if len(rules) != 4 {
		t.Fatalf("rules: %d, want 4", len(rules))
	}
	wants := []string{"ct state", "iifname lo", "tcp dport 22", "tcp dport { 80, 443 }"}
	for i, w := range wants {
		if !strings.Contains(rules[i].Expr, w) {
			t.Fatalf("rules[%d]=%q, want contains %q", i, rules[i].Expr, w)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		p       Presets
		wantErr bool
	}{
		{"empty", Presets{}, false},
		{"good port", Presets{SSH: &SSHPreset{Port: 22}}, false},
		{"port too high", Presets{SSH: &SSHPreset{Port: 70000}}, true},
		{"port negative", Presets{SSH: &SSHPreset{Port: -1}}, true},
		{"good cidr", Presets{SSH: &SSHPreset{From: []string{"10.0.0.0/8"}}}, false},
		{"bare ip", Presets{SSH: &SSHPreset{From: []string{"10.0.0.1"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
