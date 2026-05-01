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

func TestCompile_OutboundRestrict(t *testing.T) {
	tbl := Presets{Outbound: &OutboundPreset{
		Restrict: true, AllowDNS: true, AllowHTTPS: true,
	}}.Compile()
	if tbl == nil {
		t.Fatal("nil table")
	}
	if len(tbl.Chains) != 2 {
		t.Fatalf("chains=%d, want 2 (input+output)", len(tbl.Chains))
	}
	out := tbl.Chains[1]
	if out.Hook != model.HookOutput {
		t.Fatalf("output chain hook=%q", out.Hook)
	}
	if out.Policy != model.VerdictDrop {
		t.Fatalf("policy=%q, want drop", out.Policy)
	}
	exprs := ""
	for _, r := range out.Rules {
		exprs += r.Expr + "|"
	}
	for _, want := range []string{"oifname lo accept", "ct state established", "udp dport 53 accept", "tcp dport 53 accept", "tcp dport 443 accept"} {
		if !strings.Contains(exprs, want) {
			t.Fatalf("want %q in rules, got %q", want, exprs)
		}
	}
}

func TestCompile_OutboundBlockOnly(t *testing.T) {
	tbl := Presets{Outbound: &OutboundPreset{
		Block: []string{"192.0.2.0/24", "2001:db8::/32"},
	}}.Compile()
	if tbl == nil || len(tbl.Chains) != 2 {
		t.Fatalf("expected output chain, chains=%d", len(tbl.Chains))
	}
	out := tbl.Chains[1]
	if out.Policy != model.VerdictAccept {
		t.Fatalf("policy=%q, want accept (block-only mode)", out.Policy)
	}
	if len(out.Rules) != 2 {
		t.Fatalf("rules=%d, want 2 (v4+v6 drop)", len(out.Rules))
	}
	if !strings.Contains(out.Rules[0].Expr, "ip daddr") || !strings.Contains(out.Rules[0].Expr, "drop") {
		t.Fatalf("v4 drop rule: %q", out.Rules[0].Expr)
	}
}

func TestCompile_OutboundInactive(t *testing.T) {
	// All zeros = not active = no output chain.
	tbl := Presets{
		CaddyBox: true,
		Outbound: &OutboundPreset{},
	}.Compile()
	if len(tbl.Chains) != 1 {
		t.Fatalf("chains=%d, want 1", len(tbl.Chains))
	}
}

func TestCompile_SSHInterfaces(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{Interfaces: []string{"tailscale0", "wg0"}}}.Compile()
	rules := tbl.Chains[0].Rules
	if len(rules) != 1 {
		t.Fatalf("rules: %d, want 1", len(rules))
	}
	expr := rules[0].Expr
	if !strings.HasPrefix(expr, `iifname { "tailscale0", "wg0" } `) {
		t.Fatalf("expected iifname prefix, got %q", expr)
	}
	if !strings.Contains(expr, "tcp dport 22 accept") {
		t.Fatalf("missing dport: %q", expr)
	}
}

func TestCompile_SSHInterfacesSingleQuoted(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{Interfaces: []string{"tailscale0"}}}.Compile()
	expr := tbl.Chains[0].Rules[0].Expr
	if !strings.HasPrefix(expr, `iifname "tailscale0" `) {
		t.Fatalf("got %q", expr)
	}
}

func TestCompile_SSHInterfacesWithCIDR(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{
		Interfaces: []string{"wg0"},
		From:       []string{"10.0.0.0/8"},
	}}.Compile()
	expr := tbl.Chains[0].Rules[0].Expr
	if !strings.HasPrefix(expr, `iifname "wg0" ip saddr {`) {
		t.Fatalf("got %q", expr)
	}
}

func TestCompile_SSHRateLimit(t *testing.T) {
	tbl := Presets{SSH: &SSHPreset{RateLimit: &SSHRateLimit{PerMinute: 5}}}.Compile()
	rules := tbl.Chains[0].Rules
	if len(rules) != 2 {
		t.Fatalf("rules: %d, want 2 (v4+v6 throttled)", len(rules))
	}
	if !strings.Contains(rules[0].Expr, "meter ssh-throttle-v4") || !strings.Contains(rules[0].Expr, "limit rate 5/minute") {
		t.Fatalf("v4 throttle: %q", rules[0].Expr)
	}
	if !strings.Contains(rules[1].Expr, "ssh-throttle-v6") {
		t.Fatalf("v6 throttle: %q", rules[1].Expr)
	}
}

func TestValidate_SSHInterfaces(t *testing.T) {
	cases := []struct {
		name    string
		ifaces  []string
		wantErr bool
	}{
		{"good", []string{"wg0", "tailscale0"}, false},
		{"empty string", []string{""}, true},
		{"contains space", []string{"wg 0"}, true},
		{"contains brace", []string{"wg{0}"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Presets{SSH: &SSHPreset{Interfaces: tc.ifaces}}).Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_SSHRateLimit(t *testing.T) {
	if err := (Presets{SSH: &SSHPreset{RateLimit: &SSHRateLimit{PerMinute: -1}}}).Validate(); err == nil {
		t.Fatal("expected error for negative rate")
	}
	if err := (Presets{SSH: &SSHPreset{RateLimit: &SSHRateLimit{PerMinute: 5}}}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompile_BlockSetsDeclaration(t *testing.T) {
	tbl := Presets{
		BlockSets: []NamedBlockSet{
			{Name: "country-block", CIDRs: []string{"203.0.113.0/24", "198.51.100.0/24"}},
			{Name: "abuse-v6", Family: "v6", CIDRs: []string{"2001:db8::/32"}},
		},
		Outbound: &OutboundPreset{BlockRefs: []string{"country-block", "abuse-v6"}},
	}.Compile()
	if tbl == nil {
		t.Fatal("nil table")
	}
	if len(tbl.Sets) != 2 {
		t.Fatalf("sets=%d, want 2", len(tbl.Sets))
	}
	// Sorted elements
	if tbl.Sets[0].Name != "country-block" || tbl.Sets[0].Type != "ipv4_addr" {
		t.Fatalf("set 0: %+v", tbl.Sets[0])
	}
	if tbl.Sets[0].Elements[0] != "198.51.100.0/24" {
		t.Fatalf("not sorted: %v", tbl.Sets[0].Elements)
	}
	if tbl.Sets[1].Type != "ipv6_addr" {
		t.Fatalf("v6 type: %q", tbl.Sets[1].Type)
	}
	// Outbound rules referencing them
	out := tbl.Chains[1]
	gotV4, gotV6 := false, false
	for _, r := range out.Rules {
		if r.Expr == "ip6 daddr @abuse-v6 drop" {
			gotV6 = true
		}
		if r.Expr == "ip daddr @country-block drop" {
			gotV4 = true
		}
	}
	if !gotV4 || !gotV6 {
		t.Fatalf("missing block-ref rules: %+v", out.Rules)
	}
}

func TestValidate_BlockSets(t *testing.T) {
	cases := []struct {
		name    string
		p       Presets
		wantErr bool
	}{
		{"good", Presets{BlockSets: []NamedBlockSet{{Name: "x", CIDRs: []string{"10.0.0.0/8"}}}}, false},
		{"missing name", Presets{BlockSets: []NamedBlockSet{{CIDRs: []string{"10.0.0.0/8"}}}}, true},
		{"bad family", Presets{BlockSets: []NamedBlockSet{{Name: "x", Family: "v9", CIDRs: []string{"10.0.0.0/8"}}}}, true},
		{"bare ip", Presets{BlockSets: []NamedBlockSet{{Name: "x", CIDRs: []string{"10.0.0.1"}}}}, true},
		{"unknown ref", Presets{Outbound: &OutboundPreset{BlockRefs: []string{"nope"}}}, true},
		{"duplicate name", Presets{BlockSets: []NamedBlockSet{{Name: "x"}, {Name: "x"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
