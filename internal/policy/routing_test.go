package policy

import (
	"strings"
	"testing"

	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/render"
)

// renderOne returns the nft text for a single table (helper for assertions).
func renderOne(t *testing.T, tbl *model.Table) string {
	t.Helper()
	if tbl == nil {
		t.Fatal("table is nil")
	}
	rs := &model.Ruleset{Tables: []model.Table{*tbl}}
	out, err := render.String(rs, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

func TestCompileTables_EmptyWhenNothingSet(t *testing.T) {
	if got := (Presets{}).CompileTables(); len(got) != 0 {
		t.Fatalf("expected no tables, got %d", len(got))
	}
}

func TestCompileTables_NATPortForward(t *testing.T) {
	p := Presets{
		PortForwards: []PortForward{
			{Proto: "tcp", IIF: "eth0", ExtPort: 8080, To: "10.0.0.5", ToPort: 80},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tables := p.CompileTables()
	if len(tables) != 1 {
		t.Fatalf("want 1 table (nat only), got %d", len(tables))
	}
	tbl := tables[0]
	if tbl.Family != model.FamilyIP || tbl.Name != NATTableName {
		t.Fatalf("want ip zeerak-nat, got %s %s", tbl.Family, tbl.Name)
	}
	out := renderOne(t, &tbl)
	for _, want := range []string{
		"table ip zeerak-nat {",
		"type nat hook prerouting priority -100;",
		"type nat hook postrouting priority 100;",
		`iifname "eth0" tcp dport 8080 dnat to 10.0.0.5:80`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestCompileTables_NATMasquerade(t *testing.T) {
	p := Presets{
		Masquerade: []Masquerade{
			{OIF: "eth0", Source: "10.0.0.0/24"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tables := p.CompileTables()
	if len(tables) != 1 {
		t.Fatalf("want 1 table, got %d", len(tables))
	}
	out := renderOne(t, &tables[0])
	for _, want := range []string{
		`oifname "eth0" ip saddr 10.0.0.0/24 masquerade`,
		"hook postrouting priority 100",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestCompileTables_NATDeterministic(t *testing.T) {
	// Two equivalent inputs (different declaration order) -> identical output.
	a := Presets{PortForwards: []PortForward{
		{Proto: "tcp", ExtPort: 443, To: "10.0.0.5"},
		{Proto: "tcp", ExtPort: 80, To: "10.0.0.5"},
	}}
	b := Presets{PortForwards: []PortForward{
		{Proto: "tcp", ExtPort: 80, To: "10.0.0.5"},
		{Proto: "tcp", ExtPort: 443, To: "10.0.0.5"},
	}}
	out1 := renderOne(t, &a.CompileTables()[0])
	out2 := renderOne(t, &b.CompileTables()[0])
	if out1 != out2 {
		t.Fatalf("non-deterministic NAT compile:\n--- a ---\n%s\n--- b ---\n%s", out1, out2)
	}
}

func TestCompileTables_Marks(t *testing.T) {
	p := Presets{
		Marks: []Mark{
			{Name: "vpn-split", Daddr: "10.50.0.0/16", Set: 0x100},
			{Name: "voip", Proto: "udp", DPort: 5060, Set: 0x200},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tables := p.CompileTables()
	if len(tables) != 1 {
		t.Fatalf("want 1 table, got %d", len(tables))
	}
	tbl := tables[0]
	if tbl.Name != MarksTableName || tbl.Family != model.FamilyINet {
		t.Fatalf("want inet zeerak-marks, got %s %s", tbl.Family, tbl.Name)
	}
	out := renderOne(t, &tbl)
	for _, want := range []string{
		"table inet zeerak-marks {",
		"type route hook output priority -150;",
		"ip daddr 10.50.0.0/16 meta mark set 0x100",
		"udp dport 5060 meta mark set 0x200",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestCompileTables_MarksDeterministicByValue(t *testing.T) {
	// Sort by Set value: 0x50 should come before 0x100 regardless of input order.
	p := Presets{Marks: []Mark{
		{Name: "b", Set: 0x100, Daddr: "10.0.0.0/8"},
		{Name: "a", Set: 0x50, Daddr: "192.168.0.0/16"},
	}}
	out := renderOne(t, &p.CompileTables()[0])
	i50 := strings.Index(out, "0x50")
	i100 := strings.Index(out, "0x100")
	if i50 == -1 || i100 == -1 {
		t.Fatalf("missing marks in output:\n%s", out)
	}
	if i50 > i100 {
		t.Fatalf("expected 0x50 before 0x100; got\n%s", out)
	}
}

func TestCompileTables_CTHelpers(t *testing.T) {
	p := Presets{CTHelpers: &CTHelpers{FTP: true, SIP: true}}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tables := p.CompileTables()
	if len(tables) != 1 {
		t.Fatalf("want 1 table, got %d", len(tables))
	}
	tbl := tables[0]
	if tbl.Name != CTTableName || len(tbl.Helpers) != 2 {
		t.Fatalf("want zeerak-ct with 2 helpers, got %s w/%d", tbl.Name, len(tbl.Helpers))
	}
	out := renderOne(t, &tbl)
	for _, want := range []string{
		"table inet zeerak-ct {",
		`ct helper "ftp-standard" {`,
		`type "ftp" protocol tcp;`,
		`ct helper "sip-standard" {`,
		`type "sip" protocol udp;`,
		"type filter hook prerouting priority -200;",
		`tcp dport 21 ct helper set "ftp-standard"`,
		`udp dport 5060 ct helper set "sip-standard"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestCompileTables_AllThreeAtOnce(t *testing.T) {
	p := Presets{
		DefaultDenyInbound: true,
		PortForwards: []PortForward{
			{Proto: "tcp", ExtPort: 443, To: "10.0.0.5"},
		},
		Marks: []Mark{
			{Name: "split", Daddr: "10.50.0.0/16", Set: 0x100},
		},
		CTHelpers: &CTHelpers{FTP: true},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	tables := p.CompileTables()
	if len(tables) != 4 {
		t.Fatalf("want 4 tables (presets, nat, marks, ct), got %d", len(tables))
	}
	gotNames := make([]string, len(tables))
	for i, tbl := range tables {
		gotNames[i] = string(tbl.Family) + " " + tbl.Name
	}
	want := []string{
		"inet zeerak-presets",
		"ip zeerak-nat",
		"inet zeerak-marks",
		"inet zeerak-ct",
	}
	for i, w := range want {
		if gotNames[i] != w {
			t.Errorf("table[%d]: want %q, got %q", i, w, gotNames[i])
		}
	}
}

func TestValidateRouting_Errors(t *testing.T) {
	cases := []struct {
		name string
		p    Presets
		want string
	}{
		{
			"port_forward missing to",
			Presets{PortForwards: []PortForward{{ExtPort: 80}}},
			"to: required",
		},
		{
			"port_forward bad to",
			Presets{PortForwards: []PortForward{{ExtPort: 80, To: "10.0.0.5:80"}}},
			"plain IPv4 address",
		},
		{
			"port_forward proto v6",
			Presets{PortForwards: []PortForward{{Proto: "sctp", ExtPort: 80, To: "10.0.0.5"}}},
			"proto",
		},
		{
			"port_forward bad ext_port",
			Presets{PortForwards: []PortForward{{ExtPort: 0, To: "10.0.0.5"}}},
			"ext_port",
		},
		{
			"masquerade missing oif",
			Presets{Masquerade: []Masquerade{{Source: "10.0.0.0/24"}}},
			"oif: required",
		},
		{
			"mark missing set",
			Presets{Marks: []Mark{{Name: "x"}}},
			"set: required",
		},
		{
			"mark duplicate name",
			Presets{Marks: []Mark{
				{Name: "x", Set: 1},
				{Name: "x", Set: 2},
			}},
			"duplicate name",
		},
		{
			"mark dport without proto",
			Presets{Marks: []Mark{{Name: "x", Set: 1, DPort: 80}}},
			"dport requires proto",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
